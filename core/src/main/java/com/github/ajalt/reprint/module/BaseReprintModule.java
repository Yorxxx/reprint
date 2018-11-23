package com.github.ajalt.reprint.module;


import android.annotation.TargetApi;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.support.v4.os.CancellationSignal;

import com.github.ajalt.library.R;
import com.github.ajalt.reprint.core.AuthenticationFailureReason;
import com.github.ajalt.reprint.core.AuthenticationListener;
import com.github.ajalt.reprint.core.Reprint;
import com.github.ajalt.reprint.core.ReprintModule;

/**
 * Base reprint module that authenticates fingerprint using the marshmallow Imprint API.
 * <p/>
 * This module supports most phones running Android Marshmallow.
 * <p/>
 * The values of error codes provided by the api overlap for fatal and non-fatal authentication
 * failures. Fatal error code constants start with FINGERPRINT_ERROR, and non-fatal error codes
 * start with FINGERPRINT_ACQUIRED.
 */
@TargetApi(Build.VERSION_CODES.M)
@RequiresApi(Build.VERSION_CODES.M)
public abstract class BaseReprintModule implements ReprintModule {

    public static final Reprint.Logger NULL_LOGGER = new Reprint.Logger() {
        public void log(String message) {}

        public void logException(Throwable throwable, String message) {}
    };

    protected static final int TAG = -1;

    // The following FINGERPRINT constants are copied from FingerprintManager, since that class
    // isn't available pre-marshmallow, and they aren't defined in FingerprintManagerCompat for some
    // reason.

    /**
     * The hardware is unavailable. Try again later.
     */
    public static final int FINGERPRINT_ERROR_HW_UNAVAILABLE = 1;

    /**
     * Error state returned when the sensor was unable to process the current image.
     */
    public static final int FINGERPRINT_ERROR_UNABLE_TO_PROCESS = 2;

    /**
     * Error state returned when the current request has been running too long. This is intended to
     * prevent programs from waiting for the fingerprint sensor indefinitely. The timeout is
     * platform and sensor-specific, but is generally on the order of 30 seconds.
     */
    public static final int FINGERPRINT_ERROR_TIMEOUT = 3;

    /**
     * Error state returned for operations like enrollment; the operation cannot be completed
     * because there's not enough storage remaining to complete the operation.
     */
    public static final int FINGERPRINT_ERROR_NO_SPACE = 4;

    /**
     * The operation was canceled because the fingerprint sensor is unavailable. For example, this
     * may happen when the user is switched, the device is locked or another pending operation
     * prevents or disables it.
     */
    public static final int FINGERPRINT_ERROR_CANCELED = 5;

    /**
     * The operation was canceled because the API is locked out due to too many attempts.
     */
    public static final int FINGERPRINT_ERROR_LOCKOUT = 7;

    /**
     * The operation was canceled because a new fingerprint has been added to the device
     */
    public static final int FINGERPRINT_ERROR_NEW_ENROLMENT_DETECTED = 8;

    // The following ACQUIRED constants are used with help messages
    /**
     * The image acquired was good.
     */
    public static final int FINGERPRINT_ACQUIRED_GOOD = 0;

    /**
     * Only a partial fingerprint image was detected. During enrollment, the user should be informed
     * on what needs to happen to resolve this problem, e.g. "press firmly on sensor."
     */
    public static final int FINGERPRINT_ACQUIRED_PARTIAL = 1;

    /**
     * The fingerprint image was too noisy to process due to a detected condition (i.e. dry skin) or
     * a possibly dirty sensor (See {@link #FINGERPRINT_ACQUIRED_IMAGER_DIRTY}).
     */
    public static final int FINGERPRINT_ACQUIRED_INSUFFICIENT = 2;

    /**
     * The fingerprint image was too noisy due to suspected or detected dirt on the sensor. For
     * example, it's reasonable return this after multiple {@link #FINGERPRINT_ACQUIRED_INSUFFICIENT}
     * or actual detection of dirt on the sensor (stuck pixels, swaths, etc.). The user is expected
     * to take action to clean the sensor when this is returned.
     */
    public static final int FINGERPRINT_ACQUIRED_IMAGER_DIRTY = 3;

    /**
     * The fingerprint image was unreadable due to lack of motion. This is most appropriate for
     * linear array sensors that require a swipe motion.
     */
    public static final int FINGERPRINT_ACQUIRED_TOO_SLOW = 4;

    /**
     * The fingerprint image was incomplete due to quick motion. While mostly appropriate for linear
     * array sensors,  this could also happen if the finger was moved during acquisition. The user
     * should be asked to move the finger slower (linear) or leave the finger on the sensor longer.
     */
    public static final int FINGERPRINT_ACQUIRED_TOO_FAST = 5;

    /**
     * A fingerprint was read that is not registered.
     * <p/>
     * This constant is defined by reprint, and is not in the FingerprintManager.
     */
    public static final int FINGERPRINT_AUTHENTICATION_FAILED = 1001;

    protected final Context context;
    protected Reprint.Logger logger = NULL_LOGGER;

    public BaseReprintModule(Context context, Reprint.Logger logger) {
        this.context = context.getApplicationContext();
        if (logger != null) {
            this.logger = logger;
        }
    }

    // We used to use the appcompat library to load the fingerprint manager, but v25.1.0 was broken
    // on many phones. Instead, we handle the manager ourselves. FingerprintManagerCompat just
    // forwards calls anyway, so it doesn't add any value for us.
    protected FingerprintManager fingerprintManager() {
        try {
            return context.getSystemService(FingerprintManager.class);
        } catch (Exception e) {
            logger.logException(e, "Could not get fingerprint system service on API that should support it.");
        } catch (NoClassDefFoundError e) {
            logger.log("FingerprintManager not available on this device");
        }
        return null;
    }

    @Override
    public int tag() {
        return TAG;
    }

    @Override
    public boolean isHardwarePresent() {
        final FingerprintManager fingerprintManager = fingerprintManager();
        if (fingerprintManager == null) return false;
        // Normally, a security exception is only thrown if you don't have the USE_FINGERPRINT
        // permission in your manifest. However, some OEMs have pushed updates to M for phones
        // that don't have sensors at all, and for some reason decided not to implement the
        // USE_FINGERPRINT permission. So on those devices, a SecurityException is raised no matter
        // what. This has been confirmed on a number of devices, including the LG LS770, LS991,
        // and the HTC One M8.
        //
        // On Robolectric, FingerprintManager.isHardwareDetected raises an NPE.
        try {
            return fingerprintManager.isHardwareDetected();
        } catch (SecurityException | NullPointerException e) {
            logger.logException(e, "MarshmallowReprintModule: isHardwareDetected failed unexpectedly");
            return false;
        }
    }

    @Override
    public boolean hasFingerprintRegistered() throws SecurityException {
        final FingerprintManager fingerprintManager = fingerprintManager();
        return fingerprintManager != null && fingerprintManager.hasEnrolledFingerprints();
    }

    @Override
    abstract public void authenticate(CancellationSignal cancellationSignal,
                                      AuthenticationListener listener,
                                      Reprint.RestartPredicate restartPredicate);

    protected class AuthCallback extends FingerprintManager.AuthenticationCallback {
        private final Reprint.RestartPredicate restartPredicate;
        private final CancellationSignal cancellationSignal;
        private final AuthenticationListener listener;
        private int restartCount;

        public AuthCallback(int restartCount, Reprint.RestartPredicate restartPredicate,
                            CancellationSignal cancellationSignal, AuthenticationListener listener) {
            this.restartCount = restartCount;
            this.restartPredicate = restartPredicate;
            this.cancellationSignal = cancellationSignal;
            this.listener = listener;
        }

        @Override
        public void onAuthenticationError(int errMsgId, CharSequence errString) {
            AuthenticationFailureReason failureReason = AuthenticationFailureReason.UNKNOWN;
            switch (errMsgId) {
                case FINGERPRINT_ERROR_HW_UNAVAILABLE:
                    failureReason = AuthenticationFailureReason.HARDWARE_UNAVAILABLE;
                    break;
                case FINGERPRINT_ERROR_UNABLE_TO_PROCESS:
                case FINGERPRINT_ERROR_NO_SPACE:
                    failureReason = AuthenticationFailureReason.SENSOR_FAILED;
                    break;
                case FINGERPRINT_ERROR_TIMEOUT:
                    failureReason = AuthenticationFailureReason.TIMEOUT;
                    break;
                case FINGERPRINT_ERROR_LOCKOUT:
                    failureReason = AuthenticationFailureReason.LOCKED_OUT;
                    break;
                case FINGERPRINT_ERROR_CANCELED:
                    // Don't send a cancelled message.
                    return;
                case FINGERPRINT_ERROR_NEW_ENROLMENT_DETECTED:
                    failureReason = AuthenticationFailureReason.KEY_INVALID;
            }

            if (errMsgId == FINGERPRINT_ERROR_TIMEOUT && restartPredicate.invoke(failureReason, restartCount)) {
                authenticate(cancellationSignal, listener, restartPredicate);
            } else {
                listener.onFailure(failureReason, true, errString, TAG, errMsgId);
            }
        }

        @Override
        public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
            if (!restartPredicate.invoke(AuthenticationFailureReason.SENSOR_FAILED, restartCount++)) {
                cancellationSignal.cancel();
            }
            listener.onFailure(AuthenticationFailureReason.SENSOR_FAILED, false, helpString, TAG, helpMsgId);
        }

        @Override
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            listener.onSuccess(TAG);
        }

        @Override
        public void onAuthenticationFailed() {
            listener.onFailure(AuthenticationFailureReason.AUTHENTICATION_FAILED, false,
                    context.getString(R.string.fingerprint_not_recognized), TAG, FINGERPRINT_AUTHENTICATION_FAILED);
        }
    }
}
