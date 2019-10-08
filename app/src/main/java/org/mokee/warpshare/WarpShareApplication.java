/*
 * Copyright (C) 2019 The MoKee Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.mokee.warpshare;

import android.app.Application;
import android.content.Context;

import androidx.annotation.RawRes;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class WarpShareApplication extends Application {

    private static Context context;
    private static SSLContext sslContext;

    static WarpShareApplication from(Context context) {
        return (WarpShareApplication) context.getApplicationContext();
    }

    @Override
    public void onCreate() {
        WarpShareApplication.context = this.getApplicationContext();
        super.onCreate();
    }


    public static SSLContext getSSLContext() {
        InputStream caInput = null;
        try {
            // Generate the CA Certificate from the raw resource file
            caInput = WarpShareApplication.context.getResources().openRawResource(R.raw.mokee_warp_ca);
            Certificate ca = CertificateFactory.getInstance("X.509").generateCertificate(caInput);

            // Load the key store using the CA
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("ca", ca);

            // Initialize the TrustManager with this CA
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            //初始化keystore
            KeyStore clientKeyStore = KeyStore.getInstance("BKS");
            clientKeyStore.load(WarpShareApplication.context.getResources().openRawResource(R.raw.warpshare), "123456".toCharArray());
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(clientKeyStore, "123456".toCharArray());


            // Create an SSL context that uses the created trust manager
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
            return sslContext;
        } catch (Exception ex) {
            throw new RuntimeException(ex);

        } finally {
            if (caInput != null) {
                try {
                    caInput.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    public static SSLSocketFactory createSSLSocketFactory(@RawRes int caRawFile) {
        InputStream caInput = null;
        try {
            // Generate the CA Certificate from the raw resource file
            caInput = WarpShareApplication.context.getResources().openRawResource(caRawFile);
            Certificate ca = CertificateFactory.getInstance("X.509").generateCertificate(caInput);

            // Load the key store using the CA
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("ca", ca);

            // Initialize the TrustManager with this CA
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            // Create an SSL context that uses the created trust manager
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
            return sslContext.getSocketFactory();

        } catch (Exception ex) {
            throw new RuntimeException(ex);

        } finally {
            if (caInput != null) {
                try {
                    caInput.close();
                } catch (IOException ignored) {
                }
            }
        }
    }


}
