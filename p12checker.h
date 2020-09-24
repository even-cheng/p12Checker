//
//  p12checker.hpp
//  ECSignerForiOS
//
//  Created by 快游 on 2020/9/12.
//  Copyright © 2020 even_cheng. All rights reserved.
//
#include <openssl/x509.h>

bool isP12Revoked(X509 * x509, bool g3);
