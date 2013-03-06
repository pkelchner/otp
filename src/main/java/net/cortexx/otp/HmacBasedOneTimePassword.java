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
package net.cortexx.otp;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Generates HMAC-based one-time passwords according to
 * <a href="http://tools.ietf.org/html/rfc4226">RFC 4226</a>.
 * This type is thread-safe.
 * <p>
 * This class is designed to be reused per secret to generate passwords from.
 */
public final class HmacBasedOneTimePassword {
	public enum Algorithm {
		SHA1, SHA256, SHA512
	}

	private final Lock lock = new ReentrantLock();
	private final Mac mac;
	private final int truncation;

	/**
	 * Generates the password corresponding to the given counter.
	 */
	public final int generatePassword(final long counter) {
		final byte[] counterBytes = ByteBuffer.allocate(8)
				.order(ByteOrder.BIG_ENDIAN)
				.putLong(counter)
				.array();

		final byte[] hash;

		lock.lock();
		try {
			hash = mac.doFinal(counterBytes);
		} finally {
			lock.unlock();
		}

		final int offset = hash[19] & 0x0F;
		final int truncatedHash = ((ByteBuffer) ByteBuffer.wrap(hash)
				.order(ByteOrder.BIG_ENDIAN)
				.position(offset))
				.getInt() & 0x7FFFFFFF;

		return truncatedHash % truncation;
	}

	/**
	 * Generates the password corresponding to the given counter as a string,
	 * filling the string with leading zeros if necessary.
	 */
	public String generatePasswordString(final long counter) {
		final int password = generatePassword(counter);
		final StringBuilder textPassword = new StringBuilder(8);

		for (int i = truncation / 10; i > password && i > 1; i /= 10) {
			textPassword.append('0');
		}
		textPassword.append(password);

		return textPassword.toString();
	}

	/**
	 * @param algorithm
	 *        the algorithm to use for hashing. The algorithm originally defined by RFC 4226 is
	 *        SHA1.
	 * @param numberOfDigits
	 *        the number of digits returned by {@link #generatePassword(long)}
	 * @param secret
	 *        the secret to use for hashing
	 */
	public HmacBasedOneTimePassword(final Algorithm algorithm, final int numberOfDigits, final byte... secret) {
		if (algorithm == null) {
			throw new NullPointerException("algorithm");
		}
		if (secret == null) {
			throw new NullPointerException("secret");
		}
		if (secret.length == 0) {
			throw new IllegalArgumentException("'secret' must contain at least one byte");
		}

		try {
			final SecretKeySpec key = new SecretKeySpec(secret, "raw");

			mac = Mac.getInstance("hmac" + algorithm);
			mac.init(key);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		} catch (InvalidKeyException e) {
			throw new IllegalStateException(e);
		}

		switch (numberOfDigits) {
		case 6:
			truncation = 1000000;
			break;
		case 7:
			truncation = 10000000;
			break;
		case 8:
			truncation = 100000000;
			break;
		default:
			throw new IllegalArgumentException("'numberOfDigits' must be in the range [6..8]");
		}
	}
}
