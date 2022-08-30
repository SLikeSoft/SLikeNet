/*
 *  Copyright (c) 2019, SLikeSoft UG (haftungsbeschränkt)
 *
 *  This source code is  licensed under the MIT-style license found in the license.txt
 *  file in the root directory of this source tree.
 */
#pragma once

#include <openssl/evp.h> // used for EVP_xxxx

namespace SLNet
{
	namespace Experimental
	{
		namespace Crypto
		{
			class CCryptoManager
			{
			private:
				// class members
				// note: using distinct contexts for encryption/decryption to prevent potential for race conditions
				// #med - consider moving to SessionEncrypter class
				static EVP_CIPHER_CTX* m_decryptionContext;
				static EVP_CIPHER_CTX* m_encryptionContext;
				static unsigned char m_initializationVector[EVP_MAX_IV_LENGTH];
				static unsigned char m_sessionKey[EVP_MAX_KEY_LENGTH];
				static bool m_Initialized;

			public:
				// initialization
				static bool Initialize();

			public:
				// session encryption
				static bool EncryptSessionData(const unsigned char* plaintext, size_t dataLength, unsigned char* outBuffer, size_t& inOutBufferSize);
				static bool DecryptSessionData(const unsigned char* encryptedtext, size_t dataLength, unsigned char* outBuffer, size_t& inOutBufferSize);
				static bool GetRequiredEncryptionBufferSize(size_t& encryptionDataByteLength);

			public:
				// secure memory management methods
				// #med - consider moving to separate class (SecureMemory/MemoryManager)
				static void* AllocateSecureMemory(size_t size);
				static void FreeSecureMemory(void* pointer, size_t size);
				static void SecureClearMemory(void* pointer, size_t dataSize);
			};
		}
	}
}
