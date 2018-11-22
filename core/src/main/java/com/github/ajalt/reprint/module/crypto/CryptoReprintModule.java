package com.github.ajalt.reprint.module.crypto;


import android.annotation.TargetApi;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.v4.os.CancellationSignal;

import com.github.ajalt.library.R;
import com.github.ajalt.reprint.core.AuthenticationFailureReason;
import com.github.ajalt.reprint.core.AuthenticationListener;
import com.github.ajalt.reprint.core.Reprint;
import com.github.ajalt.reprint.core.ReprintModule;
import com.github.ajalt.reprint.module.BaseReprintModule;

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * A reprint module that authenticates fingerprint using the marshmallow Imprint API with Crypto object
 * that allows invalidate the key whenever the unlock screen has been deleted and when
 * the a new enrolment has been added (only on Android Oreo and above)
 * <p/>
 * This module supports most phones running Android Marshmallow.
 * <p/>
 * The values of error codes provided by the api overlap for fatal and non-fatal authentication
 * failures. Fatal error code constants start with FINGERPRINT_ERROR, and non-fatal error codes
 * start with FINGERPRINT_ACQUIRED.
 * A minor fix has to been added in order to allow to receive new enrollment errors for Android API 26.
 * https://issuetracker.google.com/issues/65578763
 */
@TargetApi(Build.VERSION_CODES.M)
@RequiresApi(Build.VERSION_CODES.M)
public class CryptoReprintModule extends BaseReprintModule implements ReprintModule {

    private static final int TAG = 3;

    private static final String DEFAULT_KEYSTORE = "AndroidKeyStore";
    private static final String DEFAULT_KEY_NAME = "myApplication";
    private static final String DEFAULT_STORE_PASS = "csdgh@jkbvj@";

    public CryptoReprintModule(Context context) {
        this(context, null);
    }

    public CryptoReprintModule(Context context, Reprint.Logger logger) {
        super(context, logger);
    }

    @Override
    public void authenticate(final CancellationSignal cancellationSignal,
                             final AuthenticationListener listener,
                             final Reprint.RestartPredicate restartPredicate) {
        authenticate(cancellationSignal, listener, restartPredicate, 0);
    }

    private KeyStore accessKeyStore(String storeName) {
        try {
            return KeyStore.getInstance(storeName);
        } catch (Throwable exc) {
            // Was not available.
            return null;
        }
    }

    private Cipher accessCipher() {
        try {
            return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // Was not available.
            return null;
        }
    }

    public boolean hasFingerprintSetChanged() {
        try {
            if (!keyExist()) {
                return false;
            }

            initCipher();
            return false;
        } catch (KeyPermanentlyInvalidatedException e) {
            return true;
        } catch (IllegalBlockSizeException e) {
            return Build.VERSION.SDK_INT == 26;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Tries to encrypt some data with the generated key from [createKey].
     * This is useful to thro
     */
    private void tryEncrypt(Cipher cipher) throws Exception {
        try {
            cipher.doFinal("Very secret message".getBytes("UTF-8"));
        } catch (IllegalBlockSizeException e) {
            if (Build.VERSION.SDK_INT == 26) {
                throw new KeyPermanentlyInvalidatedException();
            } else throw e;
        }
    }

    private Cipher initCipher() throws Exception {
        KeyStore store = accessKeyStore(DEFAULT_KEYSTORE);
        if (store == null) {
            throw new IllegalArgumentException("Keystore required or not found");
        }

        Cipher cipher = accessCipher();
        if (cipher == null) {
            throw new IllegalArgumentException("Cipher is required.");
        }

        if (!keyExist()) {
            createKey();
        }

        store.load(null);
        SecretKey key = (SecretKey) store.getKey(DEFAULT_KEY_NAME, DEFAULT_STORE_PASS.toCharArray());
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher;
    }

    private void authenticate(final CancellationSignal cancellationSignal,
                              final AuthenticationListener listener,
                              final Reprint.RestartPredicate restartPredicate,
                              final int restartCount) throws SecurityException {

        try {
            Cipher cipher = initCipher();

            final FingerprintManager fingerprintManager = fingerprintManager();

            if (fingerprintManager == null) {
                listener.onFailure(AuthenticationFailureReason.UNKNOWN, true,
                        context.getString(R.string.fingerprint_error_unable_to_process), TAG, FINGERPRINT_ERROR_CANCELED);
                return;
            }

            final FingerprintManager.AuthenticationCallback callback =
                    new CryptoAuthCallback(restartCount, restartPredicate, cancellationSignal, listener);

            // Why getCancellationSignalObject returns an Object is unexplained
            final android.os.CancellationSignal signalObject = cancellationSignal == null ? null :
                    (android.os.CancellationSignal) cancellationSignal.getCancellationSignalObject();

            // Occasionally, an NPE will bubble up out of FingerprintManager.authenticate
            fingerprintManager.authenticate(generateCryptoObject(cipher),
                    signalObject,
                    0,
                    callback,
                    null);
        } catch (KeyPermanentlyInvalidatedException e) {
            logger.logException(e, "MarshmallowReprintModule: authentication failed because key has been invalidated");
            listener.onFailure(AuthenticationFailureReason.KEY_INVALID, true,
                    context.getString(R.string.fingerprint_error_new_enrolment_detected), TAG, FINGERPRINT_ERROR_NEW_ENROLMENT_DETECTED);
        } catch (Exception e) {
            logger.logException(e, "MarshmallowReprintModule: authenticate failed unexpectedly");
            listener.onFailure(AuthenticationFailureReason.UNKNOWN, true,
                    context.getString(R.string.fingerprint_error_unable_to_process), TAG, FINGERPRINT_ERROR_CANCELED);
        }
    }

    private FingerprintManager.CryptoObject generateCryptoObject(Cipher cipher) {
        if (cipher == null) {
            throw new IllegalArgumentException("Cipher is required.");
        }
        return new FingerprintManager.CryptoObject(cipher);
    }

    public Boolean createKey() {
        try {
            KeyStore store = accessKeyStore(DEFAULT_KEYSTORE);
            if (store == null) {
                return null;
            }

            KeyGenerator generator = accessKeyGen(KeyProperties.KEY_ALGORITHM_AES, DEFAULT_KEYSTORE);
            if (generator == null) {
                return null;
            }

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    DEFAULT_KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
            )
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    // Require the user to authenticate with a fingerprint to authorize every use
                    // of the key
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);

            if (Build.VERSION.SDK_INT >= 24) {
                builder.setInvalidatedByBiometricEnrollment(true);
            }
            generator.init(builder.build());
            generator.generateKey();
            return true;
        } catch (Throwable exc) {
            logger.logException(exc, exc.getLocalizedMessage());
            return false;
        }
    }

    public Boolean keyExist() {
        try {
            KeyStore store = accessKeyStore(DEFAULT_KEYSTORE);
            if (store == null) {
                return null;
            }

            store.load(null);
            SecretKey key = (SecretKey) store.getKey(DEFAULT_KEY_NAME, DEFAULT_STORE_PASS.toCharArray());
            if (key != null) {
                return true;
            }

        } catch (Throwable exc) {
            logger.logException(exc, exc.getLocalizedMessage());
            return null;
        }
        return false;
    }

    private KeyGenerator accessKeyGen(String algo, String storeName) {
        try {
            return KeyGenerator.getInstance(algo, storeName);
        } catch (Throwable exc) {
            // Was not available.
            return null;
        }
    }

    @Override
    public int tag() {
        return TAG;
    }

    /**
     * Override the default callback so, when the auth has succeeded, try encrypting and check
     * if KeyPermanentlyInvalidatedException is thrown.
     * This is because the auth flow is not throwing this error on Android Oreo devices
     * https://issuetracker.google.com/issues/65578763
     */
    protected class CryptoAuthCallback extends AuthCallback {

        CryptoAuthCallback(int restartCount, Reprint.RestartPredicate restartPredicate,
                           CancellationSignal cancellationSignal, AuthenticationListener listener) {
            super(restartCount, restartPredicate, cancellationSignal, listener);
        }

        @Override
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            try {
                // https://issuetracker.google.com/issues/65578763
                tryEncrypt(result.getCryptoObject().getCipher());
                super.onAuthenticationSucceeded(result);
            } catch (KeyPermanentlyInvalidatedException e) {
                onAuthenticationError(FINGERPRINT_ERROR_NEW_ENROLMENT_DETECTED, context.getString(R.string.fingerprint_error_new_enrolment_detected));
            } catch (IllegalBlockSizeException e) {
                if (Build.VERSION.SDK_INT == 26) {
                    onAuthenticationError(FINGERPRINT_ERROR_NEW_ENROLMENT_DETECTED, context.getString(R.string.fingerprint_error_new_enrolment_detected));
                }
                else {
                    onAuthenticationFailed();
                }
            } catch (Exception e) {
                onAuthenticationFailed();
            }
        }
    }
}
