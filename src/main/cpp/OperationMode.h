// Copyright (C) 2026 Hideaki Narita

#ifndef MYCRYPTO_OPERATIONMODE_H
#define MYCRYPTO_OPERATIONMODE_H

namespace hnrt
{
	enum OperationMode
	{
		OPERATION_UNSPECIFIED = 0,
		ENCRYPTION = 257,
		DECRYPTION,
		DIGEST = 65536
	};
}

#endif //!MYCRYPTO_OPERATIONMODE_H
