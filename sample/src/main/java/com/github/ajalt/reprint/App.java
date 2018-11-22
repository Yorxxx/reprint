package com.github.ajalt.reprint;

import android.app.Application;
import android.os.Build;
import android.util.Log;

import com.github.ajalt.reprint.core.Reprint;
import com.github.ajalt.reprint.module.crypto.CryptoReprintModule;

public class App extends Application {
    @Override
    public void onCreate() {
        super.onCreate();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Reprint.initialize(this);
            Reprint.registerModule(new CryptoReprintModule(getApplicationContext()));
        }
        else {
            Reprint.initialize(this);
        }
    }
}
