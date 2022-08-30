/*
 *  Copyright (c) 2018-2019, SLikeSoft UG (haftungsbeschränkt)
 *
 *  This source code is  licensed under the MIT-style license found in the license.txt
 *  file in the root directory of this source tree.
 */
#include "slikenet/crypto/fileencrypter.h"

#include <cstring> // used for strlen, strcpy_s

#include <openssl/err.h> // used for ERR_xxxx
#include <openssl/evp.h> // used for EVP_xxx
#include <openssl/pem.h> // used for PEM_read_bio_RSAPrivateKey, PEM_read_bio_RSA_PUBKEY, BIO_xxx
#include <openssl/rsa.h> // used for RSA_xxxx

#include "slikenet/crypto/cryptomanager.h" // used for SLNet::Experimental::Crypto::CCryptoManager
#include "slikenet/assert.h"               // used for RakAssert

#include "slikenet/linux_adapter.h" // used for strcpy_s
#include "slikenet/osx_adapter.h"   // used for strcpy_s

namespace SLNet
{
	namespace Experimental
	{
		namespace Crypto
		{
			CFileEncrypter::CFileEncrypter() :
				m_privateKey(nullptr),
				m_privatePKey(nullptr),
				m_publicKey(nullptr),
				m_publicPKey(nullptr)
			{
				CCryptoManager::Initialize();
			}

			CFileEncrypter::CFileEncrypter(const char *publicKey, size_t publicKeyLength) :
				m_privateKey(nullptr),
				m_privatePKey(nullptr),
				m_publicKey(nullptr),
				m_publicPKey(nullptr)
			{
				CCryptoManager::Initialize();

				// #high - error / exception handling
				(void)SetPublicKey(publicKey, publicKeyLength);
			}

			CFileEncrypter::CFileEncrypter(const char *publicKey, size_t publicKeyLength, const char *privateKey, size_t privateKeyLength, CSecureString &password) :
				m_privateKey(nullptr),
				m_privatePKey(nullptr),
				m_publicKey(nullptr),
				m_publicPKey(nullptr)
			{
				CCryptoManager::Initialize();

				// #high - error / exception handling
				(void)SetPrivateKey(privateKey, privateKeyLength, password);
				(void)SetPublicKey(publicKey, publicKeyLength);
			}

			CFileEncrypter::~CFileEncrypter()
			{
				// ensure that either both key elements are null or both are non-null
				RakAssert(m_publicPKey == nullptr || m_publicKey != nullptr);
				RakAssert(m_privatePKey == nullptr || m_privateKey != nullptr);

				if (m_publicPKey != nullptr) {
					EVP_PKEY_free(m_publicPKey); // implicitly frees the linked m_publicKey
				}

				if (m_privatePKey != nullptr) {
					EVP_PKEY_free(m_privatePKey); // implicitly frees the linked m_privateKey
				}
			}

			const unsigned char* CFileEncrypter::SignData(const unsigned char *data, const size_t dataLength)
			{
				if (m_privateKey == nullptr) {
					// #high - error/exception handling
					return nullptr;
				}

				EVP_MD_CTX *const rsaSigningContext = EVP_MD_CTX_create();
				// #med - double check this - it's not documented whether EVP_MD_CTX_create() can actually fail (and return null)
				if (rsaSigningContext == nullptr) {
					// #high - error/exception handling
					return nullptr;
				}

				if (EVP_SignInit_ex(rsaSigningContext, EVP_sha512(), nullptr) == 0) {
					// #high - error/exception handling
					EVP_MD_CTX_destroy(rsaSigningContext);
					return nullptr;
				}

				if (EVP_SignUpdate(rsaSigningContext, data, dataLength) == 0) {
					// #high - error/exception handling
					EVP_MD_CTX_destroy(rsaSigningContext);
					return nullptr;
				}

				// #med - use ArraySize<>()?
				unsigned int bufferSize = 1024;
				// #high - verify returned bufferSize...
				const bool success = (EVP_SignFinal(rsaSigningContext, m_sigBuffer, &bufferSize, m_privatePKey) != 0);

				// #med - review the return value here - it's not documented in the manual
				// note: cleanup() must be called so to not leak resources generated during the EVP_SignalFinal()-call
				(void)EVP_MD_CTX_reset(rsaSigningContext);
				EVP_MD_CTX_destroy(rsaSigningContext);

				return success ? m_sigBuffer : nullptr;
			}

			const char* CFileEncrypter::SignDataBase64(const unsigned char *data, const size_t dataLength)
			{
				const unsigned char* signature = SignData(data, dataLength);
				if (signature == nullptr) {
					// #high - error reporting
					return nullptr;
				}

				// #high - const_cast... / reinterpret_cast
				// 1024 binary -> 1368 base64-encoded (excluding the written null-terminator)
				if (EVP_EncodeBlock(reinterpret_cast<unsigned char*>(m_sigBufferBase64), const_cast<unsigned char*>(signature), 1024) != 1368) {
					// #high - error reporting
					return nullptr;
				}
				return m_sigBufferBase64;
			}

			// #med - consider dropping signatureLength and replace it with a fixed size unsigned char array
			//        since the signature must be 1024 chars long
			bool CFileEncrypter::VerifyData(const unsigned char *data, const size_t dataLength, const unsigned char *signature, const size_t signatureLength)
			{
				EVP_MD_CTX *const rsaVerifyContext = EVP_MD_CTX_create();
				// #med - double check this - it's not documented whether EVP_MD_CTX_create() can actually fail (and return null)
				if (rsaVerifyContext == nullptr) {
					// #high - error/exception handling
					return false;
				}

				// missing EVP_PKEY_free() call --- actually this will also destroy the RSA_KEY!!!!
				if (EVP_DigestVerifyInit(rsaVerifyContext, nullptr, EVP_sha512(), nullptr, m_publicPKey) <= 0) {
					// #high - error/exception handling
					EVP_MD_CTX_destroy(rsaVerifyContext);
					return false;
				}

				if (EVP_DigestVerifyUpdate(rsaVerifyContext, data, dataLength) <= 0) {
					// #high - error/exception handling
					EVP_MD_CTX_destroy(rsaVerifyContext);
					return false;
				}

				// #high - review const_cast / also code simplifications
				const int authenticStatus = EVP_DigestVerifyFinal(rsaVerifyContext, const_cast<unsigned char*>(signature), signatureLength);
				// #med - review the return value here - it's not documented in the manual
				// note: cleanup() must be called so to not leak resources generated during the EVP_SignalFinal()-call
				(void)EVP_MD_CTX_reset(rsaVerifyContext);
				EVP_MD_CTX_destroy(rsaVerifyContext);

				if (authenticStatus == 1) {
					return true;
				}

				// #high - add error logging/reporting
				return false;
			}

			bool CFileEncrypter::VerifyDataBase64(const unsigned char *data, const size_t dataLength, const char *signature, const size_t signatureLength)
			{
				if (signatureLength != 1368) {
					// #high error reporting
					return false; // signature has an incorrect size (1024 binary -> 1368 Base64)
				}

				// #high - casts... / signatureLength should be 1026 (1024 plus 2 padding bytes)
				if (EVP_DecodeBlock(m_sigBuffer, reinterpret_cast<const unsigned char*>(signature), static_cast<int>(signatureLength)) != 1026) {
					// #high error reporting
					return false;
				}

				// 1026 minus two padding bytes -> 1024
				return VerifyData(data, dataLength, m_sigBuffer, 1024);
			}

			int CFileEncrypter::PasswordCallback(char *buffer, int bufferSize, int, void *password)
			{
				CSecureString *securePassword = reinterpret_cast<CSecureString*>(password);
				const char *decryptedPassword = securePassword->Decrypt();
				const size_t passwordLength = strlen(decryptedPassword);
				if (passwordLength >= (size_t)bufferSize) {
					securePassword->FlushUnencryptedData();
					return -1;
				}
				strcpy_s(buffer, bufferSize, decryptedPassword);
				securePassword->FlushUnencryptedData();
				// note: static cast safe here --- already ensured that it's < bufferSize and bufferSize is of type int
				return static_cast<int>(passwordLength);
			}

			const char* CFileEncrypter::SetPrivateKey(const char *privateKey, size_t privateKeyLength, CSecureString &password)
			{
				const char *error = "";

				if (m_privatePKey != nullptr) {
					EVP_PKEY_free(m_privatePKey);
					m_privatePKey = nullptr;
					// note: m_privateKey will be set below
				}

				// #med - review interface handling (const cast...)
				// #high - size_t -> int cast...
				BIO *const keyBIO = BIO_new_mem_buf(const_cast<char*>(privateKey), static_cast<int>(privateKeyLength));

				// #high - error/exception handling
				m_privateKey = PEM_read_bio_RSAPrivateKey(keyBIO, &m_privateKey, &PasswordCallback, &password);
				if (m_privateKey == nullptr) {
					error = ERR_error_string(ERR_get_error(), nullptr);
				}

				// #high - add error check/handling if BIO_free() fails
				BIO_free(keyBIO);

				if (m_privateKey == nullptr) {
					return error; // failed to load the private key
				}

				// create the corresponding EVP_PKEY
				m_privatePKey = EVP_PKEY_new();
				if (m_privatePKey == nullptr) {
					// #high - error/exception handling
					error = ERR_error_string(ERR_get_error(), nullptr);
					RSA_free(m_privateKey);
					m_privateKey = nullptr;
					return error; // failed to allocate the PKEY struct
				}

				// #med - review interface handling (const cast...)
				if (EVP_PKEY_assign_RSA(m_privatePKey, m_privateKey) == 0) {
					// #high - error/exception handling
					error = ERR_error_string(ERR_get_error(), nullptr);
					// #high - review the error handling here --- if EVP_PKEY_assign_RSA() succeeds, freeing the pkey will implicitly also free the public key
					//         but what is the behavior upon a failure in that case?
					//         for now better accept a potential resource/mem leak rather than provoking a crash
					EVP_PKEY_free(m_privatePKey);
					m_privateKey = nullptr;
					m_privatePKey = nullptr;
					return error;
				}

				return error;
			}

			const char* CFileEncrypter::SetPublicKey(const char* publicKey, size_t publicKeyLength)
			{
				const char *error = "";

				if (m_publicPKey != nullptr) {
					EVP_PKEY_free(m_publicPKey);
					m_publicPKey = nullptr;
					// note: m_publicKey will be set below
				}

				// #med - review interface handling (const cast...)
				// #high - size_t -> int cast...
				BIO *const keyBIO = BIO_new_mem_buf(const_cast<char*>(publicKey), static_cast<int>(publicKeyLength));

				// #high - error/exception handling
				// #high - review &m_publicKey
				m_publicKey = PEM_read_bio_RSA_PUBKEY(keyBIO, &m_publicKey, nullptr, nullptr);
				if (m_publicKey == nullptr) {
					error = ERR_error_string(ERR_get_error(), nullptr);
				}

				// #high - add error check/handling if BIO_free() fails
				BIO_free(keyBIO);

				if (m_publicKey == nullptr) {
					return error; // failed to load the public key
				}

				// create the corresponding EVP_PKEY
				m_publicPKey = EVP_PKEY_new();
				if (m_publicPKey == nullptr) {
					// #high - error/exception handling
					error = ERR_error_string(ERR_get_error(), nullptr);
					RSA_free(m_publicKey);
					m_publicKey = nullptr;
					return error; // failed to allocate the PKEY struct
				}

				// #med - review interface handling (const cast...)
				if (EVP_PKEY_assign_RSA(m_publicPKey, m_publicKey) == 0) {
					// #high - error/exception handling
					error = ERR_error_string(ERR_get_error(), nullptr);
					// #high - review the error handling here --- if EVP_PKEY_assign_RSA() succeeds, freeing the pkey will implicitly also free the public key
					//         but what is the behavior upon a failure in that case?
					//         for now better accept a potential resource/mem leak rather than provoking a crash
					EVP_PKEY_free(m_publicPKey);
					m_publicKey = nullptr;
					m_publicPKey = nullptr;
					return error;
				}

				return error;
			}
		}
	}
}
