/*
 * Copyright 2013 Patrick Kelchner
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.cortexx.otp.google;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import net.cortexx.otp.HmacBasedOneTimePassword.Algorithm;

import org.apache.commons.codec.binary.Base32;

/**
 * Utility functions for use with <a href="http://code.google.com/p/google-authenticator/">Google
 * Authenticator</a>.
 * 
 * <p>
 * <b>Note:</b> This class requires the optional <a
 * href="http://commons.apache.org/proper/commons-codec/"><code>commons-codec</code></a> dependency.
 * 
 * <p>
 * Example to generate a QR Code from a generated Authenticator URI with the <a
 * href="http://code.google.com/p/zxing/"><code>zxing</code></a> library:
 * 
 * <pre>import com.google.zxing.BarcodeFormat;
 *import com.google.zxing.client.j2se.MatrixToImageWriter;
 *import com.google.zxing.common.BitMatrix;
 *import com.google.zxing.qrcode.QRCodeWriter;
 *
 *BitMatrix matrix = new QRCodeWriter().encode(
 *    GoogleAuthenticator.createDefaultTimeBasedURI("account", secret), 
 *    BarcodeFormat.QR_CODE, 
 *    250, 250);
 *    
 *MatrixToImageWriter.writeToFile(matrix, "PNG", new File("totp.png"));</pre>
 */
public class GoogleAuthenticator {
	/**
	 * Creates a URI for a time-based one-time password consumable by the
	 * <a href="http://code.google.com/p/google-authenticator/">Google Authenticator</a>.
	 * 
	 * <p>
	 * <b>Note:</b> This class requires the optional <a
	 * href="http://commons.apache.org/proper/commons-codec/"><code>commons-codec</code></a>
	 * dependency.
	 * 
	 * @param description
	 *        the display name for the token inside the Authenticator
	 * @param algorithm
	 *        the algorithm to be used
	 * @param digits
	 *        the number of digits for this password
	 * @param periodSeconds
	 *        the length of the period for which one password value stays valid
	 * @param secret
	 *        the secret for the password
	 * 
	 * @return
	 *         the <code>otpauth</code> URI corresponding to the given parameters
	 * 
	 * @see <a href="http://code.google.com/p/google-authenticator/wiki/KeyUriFormat">restrictions
	 *      applying to the Google Authenticator</a>
	 */
	public static String createTimeBasedURI(final String description,
			final Algorithm algorithm, final int digits, final int periodSeconds,
			final byte... secret) {

		if (description == null || algorithm == null || secret == null) {
			throw new NullPointerException();
		}
		if (description.length() == 0) {
			throw new IllegalArgumentException("'description' must not be empty");
		}
		if (secret.length == 0) {
			throw new IllegalArgumentException("'secret' must contain at least one byte");
		}
		if (digits < 6 || digits > 8) {
			throw new IllegalArgumentException("'digits' must be in the range [6..8]");
		}
		if (periodSeconds <= 0) {
			throw new IllegalArgumentException("'periodSeconds' must be positive");
		}

		try {
			final StringBuilder uri = new StringBuilder()
					.append("otpauth://totp/")
					.append(URLEncoder.encode(description, "UTF-8"))
					.append("?secret=")
					.append(new Base32().encodeToString(secret));

			if (algorithm != Algorithm.SHA1) {
				uri.append("&algorithm=").append(algorithm);
			}
			if (digits != 6) {
				uri.append("&digits=").append(digits);
			}
			if (periodSeconds != 30) {
				uri.append("&period=").append(periodSeconds);
			}

			return uri.toString();
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * Equivalent to the call {@link #createCounterBasedURI(String, Algorithm, int, long, byte...)
	 * createCounterBasedURI(description, SHA1, 6, 30, secret)}.
	 */
	public static String createDefaultTimeBasedURI(final String description, final byte... secret) {
		return createTimeBasedURI(description, Algorithm.SHA1, 6, 30, secret);
	}

	/**
	 * Creates a URI for a counter-based one-time password consumable by the
	 * <a href="http://code.google.com/p/google-authenticator/">Google Authenticator</a>.
	 * 
	 * <p>
	 * <b>Note:</b> This class requires the optional <a
	 * href="http://commons.apache.org/proper/commons-codec/"><code>commons-codec</code></a>
	 * dependency.
	 * 
	 * @param description
	 *        the display name for the token inside the Authenticator
	 * @param algorithm
	 *        the algorithm to be used.
	 * @param digits
	 *        the number of digits for this password
	 * @param counter
	 *        the counter this counter-based password is initialized with
	 * @param secret
	 *        the secret for the token.
	 * 
	 * @return
	 *         the <code>otpauth</code> URI corresponding to the given parameters
	 * 
	 * @see <a href="http://code.google.com/p/google-authenticator/wiki/KeyUriFormat">restrictions
	 *      applying to the Google Authenticator</a>
	 */
	public static String createCounterBasedURI(final String description,
			final Algorithm algorithm, final int digits, final long counter,
			final byte... secret) {

		if (description == null || algorithm == null || secret == null) {
			throw new NullPointerException();
		}
		if (description.length() == 0) {
			throw new IllegalArgumentException("'description' must not be empty");
		}
		if (secret.length == 0) {
			throw new IllegalArgumentException("'secret' must contain at least one byte");
		}
		if (digits < 6 || digits > 8) {
			throw new IllegalArgumentException("'digits' must be in the range [6..8]");
		}
		if (counter < 0) {
			throw new IllegalArgumentException("'counter' must be non-negative");
		}

		try {
			final StringBuilder uri = new StringBuilder()
					.append("otpauth://hotp/")
					.append(URLEncoder.encode(description, "UTF-8"))
					.append("?secret=")
					.append(new Base32().encodeToString(secret))
					.append("&counter=")
					.append(counter);

			if (algorithm != Algorithm.SHA1) {
				uri.append("&algorithm=").append(algorithm);
			}
			if (digits != 6) {
				uri.append("&digits=").append(digits);
			}

			return uri.toString();
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * Equivalent to the call {@link #createCounterBasedURI(String, Algorithm, int, long, byte...)
	 * createCounterBasedURI(description, SHA1, 6, 0, secret)}.
	 */
	public static String createDefaultCounterBasedURI(final String description, final byte... secret) {
		return createCounterBasedURI(description, Algorithm.SHA1, 6, 0, secret);
	}
}
