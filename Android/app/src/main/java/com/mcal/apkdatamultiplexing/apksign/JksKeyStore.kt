package com.mcal.apkdatamultiplexing.apksign

import java.security.KeyStore
import java.security.Provider

class JksKeyStore(provider: Provider) : KeyStore(JKS(), provider, "jks")