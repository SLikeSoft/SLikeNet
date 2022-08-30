/*
*  Copyright (c) 2019, SLikeSoft UG (haftungsbeschränkt)
*
*  This source code is  licensed under the MIT-style license found in the license.txt
*  file in the root directory of this source tree.
*/
#include "slikenet/crypto/cryptomanager.h"

#include "slikenet/assert.h" // used for RakAssert
#include <limits>            // used for std::numeric_limits<>

// prevent max/min macros getting defined (breaking numeric_limits<>::max() / ::min() usage) through the indirect windows.h include in the OpenSSL includes
#ifdef _WIN32
#define NOMINMAX
#endif

#include <openssl/err.h>     // used for ERR_xxxx
#include <openssl/evp.h>     // used for EVP_xxxx, OpenSSL_add_all_algorithms()
#include <openssl/rand.h>    // used for RAND_xxxx

namespace SLNet
{
	namespace Experimental
	{
		namespace Crypto
		{
			bool CCryptoManager::Initialize()
			{
				if (m_Initialized) {
					return true; // already initialized
				}

				ERR_load_crypto_strings();
				OpenSSL_add_all_algorithms();

#ifdef _WIN32
				// #med - once OpenSSL support for older OpenSSL versions is dropped, just remove this call - newer OpenSSL versions provide proper entropy
				//        also on Windows platforms - https://security.stackexchange.com/questions/7718/openssl-rand-poll-good-enough
				// RAND_screen() is only required on Windows - on Linux RAND_poll() will be used (called implicitly by the following RAND_bytes()-call) and
				// provides OS-specific entropy quality.
				// #high - replace with EGADS
				RAND_screen();
#endif

				if (RAND_bytes(m_sessionKey, EVP_MAX_KEY_LENGTH) == 0) {
					return false; // failed to initialize the random session key
				}
				if (RAND_bytes(m_initializationVector, EVP_MAX_IV_LENGTH) == 0) {
					return false; // failed to initialize the initialization vector
				}

				m_Initialized = true;
				return true;
			}

			bool CCryptoManager::EncryptSessionData(const unsigned char* plaintext, size_t dataLength, unsigned char* outBuffer, size_t& inOutBufferSize)
			{
				if (!Initialize()) {
					return false; // CryptoManager failed to initialize
				}

				size_t requiredBufferSize = dataLength;
				if (!GetRequiredEncryptionBufferSize(requiredBufferSize)) {
					return false; // dataLength too large (integer overflow)
				}
				if (inOutBufferSize < requiredBufferSize) {
					return false; // out buffer (potentially) too small
				}

				// #high - review usage of the CBC mode here --- not the best nowadays
				// #med - add engine support to use HW-acceleration
				if (EVP_EncryptInit_ex(m_encryptionContext, EVP_aes_256_cbc(), nullptr, m_sessionKey, m_initializationVector) == 0) {
					return false; // failed to initialize the encryption context
				}

				int bytesWritten1;
				// note: static_cast<> safe here, since GetRequiredEncrpytionBufferSize()-check ensured dataLength is <= int::max()
				if (EVP_EncryptUpdate(m_encryptionContext, outBuffer, &bytesWritten1, plaintext, static_cast<int>(dataLength)) == 0) {
					return false; // encryption failed
				}
				RakAssert(static_cast<size_t>(bytesWritten1) <= inOutBufferSize);
				int bytesWritten2;
				if (EVP_EncryptFinal_ex(m_encryptionContext, outBuffer + bytesWritten1, &bytesWritten2) == 0) {
					return false; // failed final encryption step
				}
				RakAssert(static_cast<size_t>(bytesWritten1) + static_cast<size_t>(bytesWritten2) <= inOutBufferSize);

				inOutBufferSize = static_cast<size_t>(bytesWritten1) + static_cast<size_t>(bytesWritten2);
				return true;
			}

			bool CCryptoManager::DecryptSessionData(const unsigned char* encryptedtext, size_t dataLength, unsigned char* outBuffer, size_t& inOutBufferSize)
			{
				if (!Initialize()) {
					return false; // CryptoManager failed to initialize
				}

				// #med - extend support for inOutBufferSize > int::max()
				if (inOutBufferSize > static_cast<size_t>(std::numeric_limits<int>::max())) {
					// note: We check the inOutBufferSize here rather than the dataLength due to the indirect size limitation due to the EVP_DecryptUpdate()/EVP_DecryptFinal_ex() calls
					//       being limited to int::max() through their returned written bytes values. Due to the next check (inOutBufferSize < dataLength) it's implicitly ensured that
					//       dataLength doesn't exceed the limit either.
					return false; // specified length exceeds max supported size
				}

				if (inOutBufferSize < dataLength) {
					// prevent potential buffer overflow, even though it's possible that the encryptedtext is padded and hence the effectively required
					// inOutBufferSize is less than the provided dataLength, since we cannot determine this before running the actual decryption - so consider
					// this an invalid call, if the provided inOutBufferSize is smaller than the incoming encrypted text's length
					return false;
				}

				// #high - review usage of the CBC mode here --- not the best nowadays
				// #med - add engine support to use HW-acceleration
				if (EVP_DecryptInit_ex(m_decryptionContext, EVP_aes_256_cbc(), nullptr, m_sessionKey, m_initializationVector) == 0) {
					return false; // failed to initialize the decryption context
				}

				int bytesWritten1;
				// static cast safe due to size-check above
				if (EVP_DecryptUpdate(m_decryptionContext, outBuffer, &bytesWritten1, encryptedtext, static_cast<int>(dataLength)) == 0) {
					return false; // decryption failed
				}
				RakAssert(static_cast<size_t>(bytesWritten1) <= inOutBufferSize);
				int bytesWritten2;
				if (EVP_DecryptFinal_ex(m_decryptionContext, outBuffer + bytesWritten1, &bytesWritten2) == 0) {
					return false; // failed final decryption step
				}
				RakAssert(static_cast<size_t>(bytesWritten1) + static_cast<size_t>(bytesWritten2) <= inOutBufferSize);

				inOutBufferSize = static_cast<size_t>(bytesWritten1) + static_cast<size_t>(bytesWritten2);
				return true;
			}

			bool CCryptoManager::GetRequiredEncryptionBufferSize(size_t& encryptionDataByteLength)
			{
				// note: not using EVP_CIPHER_CTX_block_size() here, since otherwise we would have to make sure that the encryption context was initialized already
				const int blockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());

				// EVP_EncryptUpdate() can write up to dataLength + blockSize - 1. The final EVP_EncryptFinal_ex() call can write up to blockSize. (reference: OpenSSL 1.0.2 documentation)
				// Hence, by definition the required encryption buffer size is dataLength + blockSize*2 -1.
				// Note: Practically the limit should actually never exceed dataLength + blockSize due to the encryption we use (AES 256 / CBC). However, we want to be safe
				//       on the design level to prevent possible incompatibilities with future OpenSSL changes.

				if (encryptionDataByteLength + blockSize * 2 - 1 < encryptionDataByteLength) {
					return false; // prevent integer overflow
				}

				encryptionDataByteLength = encryptionDataByteLength + blockSize * 2 - 1;

				// #med - extend support for datalength > int::max()
				// verify that the specified length doesn't exceed the max supported data length
				return encryptionDataByteLength <= static_cast<size_t>(std::numeric_limits<int>::max());
			}

			void* CCryptoManager::AllocateSecureMemory(size_t size)
			{
				// #high - route through memory manager (aka: same as OP_NEW_ARRAY)
				return OPENSSL_malloc(size);
			}

			void CCryptoManager::FreeSecureMemory(void* pointer, size_t size)
			{
				// make sure the memory is cleared before it's freed again
				SecureClearMemory(pointer, size);

				// #high - route through memory manager (aka: same as OP_NEW_ARRAY)
				return OPENSSL_free(pointer);
			}

			void CCryptoManager::SecureClearMemory(void* pointer, size_t size)
			{
				OPENSSL_cleanse(pointer, size);
			}

			// initialization list
			EVP_CIPHER_CTX* CCryptoManager::m_decryptionContext = EVP_CIPHER_CTX_new();
			EVP_CIPHER_CTX* CCryptoManager::m_encryptionContext = EVP_CIPHER_CTX_new();
			unsigned char CCryptoManager::m_sessionKey[EVP_MAX_KEY_LENGTH];
			unsigned char CCryptoManager::m_initializationVector[EVP_MAX_IV_LENGTH];
			bool CCryptoManager::m_Initialized = false;
		}
	}
}
