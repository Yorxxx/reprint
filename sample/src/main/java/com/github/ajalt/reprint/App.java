package com.github.ajalt.reprint;

import android.app.Application;
import android.os.Build;
import android.util.Log;

import com.github.ajalt.reprint.core.Reprint;
import com.github.ajalt.reprint.module.crypto.CryptoReprintModule;

public class App extends Application {

    private static final String DEFAULT_STORE_PASS = "csdgh@jkbvj@";
    private static final String DEFAULT_KEY_NAME = "myApplication";

    @Override
    public void onCreate() {
        super.onCreate();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Reprint.initialize(this);
            CryptoReprintModule module = new CryptoReprintModule(getApplicationContext());
            module.setKeyStoreAccess(DEFAULT_KEY_NAME, DEFAULT_STORE_PASS);
            if (!module.keyExist()) {
                module.createKey();
            }
            Reprint.registerModule(module);
        }
        else {
            Reprint.initialize(this);
        }
    }
}
