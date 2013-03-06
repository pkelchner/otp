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

import static java.util.concurrent.TimeUnit.MILLISECONDS;

import java.util.concurrent.TimeUnit;

/**
 * Generates and validates time-based {@link HmacBasedOneTimePassword}s according to
 * <a href="http://tools.ietf.org/html/rfc6238">RFC 6238</a>.
 * This type is thread-safe.
 * <p>
 * The parameters managed by this class are system parameters. This means there should be one
 * instance of this class per set of parameters in use by the system.
 */
public final class TimeBasedOneTimePassword {
	private final long slotMillis;
	private final int variance;

	/**
	 * @param timeslotLength
	 *        the length of the period one password stays valid
	 * @param timeslotLengthUnit
	 *        the unit of the length of the period
	 * @param timeslotVariance
	 *        the number of periods before and after the current period that are also considered
	 *        valid.
	 *        This mitigates time-differences between the authenticating party and the authenticated
	 *        party.
	 */
	public TimeBasedOneTimePassword(
			final long timeslotLength, final TimeUnit timeslotLengthUnit,
			final int timeslotVariance) {

		if (timeslotLengthUnit == null) {
			throw new NullPointerException("timeslotLengthUnit");
		}
		if (timeslotLength <= 0) {
			throw new IllegalArgumentException("'timeslotLength' must be positive");
		}
		if (timeslotVariance <= 0) {
			throw new IllegalArgumentException("'timeslotVariance' must be positive");
		}

		this.slotMillis = MILLISECONDS.convert(timeslotLength, timeslotLengthUnit);
		this.variance = timeslotVariance;
	}

	/**
	 * Validates that the give password is the currently valid password
	 * 
	 * @param password
	 *        the password to be validated
	 * @param otp
	 *        the one-time password to validate against
	 * @return <code>true</code> if the given password is valid, <code>false</code> if not.
	 */
	public final boolean validate(final int password, final HmacBasedOneTimePassword otp) {
		long timeslot = System.currentTimeMillis() / slotMillis;

		for (int i = -variance; i <= variance; ++i) {
			if (password == otp.generatePassword(timeslot + i)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Generates the currently valid password
	 * 
	 * @param otp
	 *        the one-time password to generate from
	 * @return
	 *         the currently valid password
	 */
	public final int generatePassword(final HmacBasedOneTimePassword otp) {
		return otp.generatePassword(System.currentTimeMillis() / slotMillis);
	}

	/**
	 * Generates the currently valid password as a string,
	 * filling the string with leading zeros if necessary.
	 * 
	 * @param otp
	 *        the one-time password to generate from
	 * @return
	 *         the currently valid password
	 */
	public final String generatePasswordString(final HmacBasedOneTimePassword otp) {
		return otp.generatePasswordString(System.currentTimeMillis() / slotMillis);
	}
}
