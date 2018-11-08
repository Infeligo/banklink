/**
 *   Copyright 2014 Nortal AS
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
package com.nortal.banklink.core.packet.nordea;

import com.nortal.banklink.core.BanklinkException;
import com.nortal.banklink.core.algorithm.Algorithm;
import com.nortal.banklink.core.log.PacketLog;
import com.nortal.banklink.core.log.PacketSignLog;
import com.nortal.banklink.core.log.PacketVerifyLog;
import com.nortal.banklink.core.packet.Packet;
import com.nortal.banklink.core.packet.param.PacketParameter;
import org.slf4j.LoggerFactory;

/**
 * The Class NordeaPaymentPacket.
 */
public class NordeaPaymentPacket extends Packet {

    /**
     * Instantiates a new nordea payment packet.
     * 
     * @param id
     *            the id
     * @param algorithm
     *            the algorithm
     */
    @SuppressWarnings("rawtypes")
    protected NordeaPaymentPacket(String id, Algorithm algorithm) {
        super(id, algorithm);
    }

    /**
     * Override for Nordea.
     * 
     * @throws BanklinkException
     *             the banklink exception
     * @see Packet#sign()
     */
    @Override
    public void sign() throws BanklinkException {

        try {

            String macString = algorithm.sign(parameters());

            // begin logging
            PacketLog pl = new PacketSignLog();
            for (PacketParameter parameter : parameters()) {
                pl.setParameter(parameter.getName(), parameter.getValue());

            }

            pl.setParameter("STRING", algorithm.getMacString(parameters()));
            pl.setParameter("SIGNATURE", macString);
            LoggerFactory.getLogger(pl.getClass()).trace(pl.toString());
            // end logging

            setParameter(getMacName(), macString);

        } catch (Exception e) {
            throw new BanklinkException(e.toString(), e);
        }

    }

    /**
     * Override.
     * 
     * @return true, if successful
     * @throws BanklinkException
     *             the banklink exception
     * @see Packet#verify()
     */
    @Override
    public boolean verify() throws BanklinkException {

        try {

            String macString = getParameterValue(getMacName());

            boolean answer = algorithm.verify(parameters(), macString);

            // begin logging
            PacketLog pl = new PacketVerifyLog();
            for (PacketParameter parameter : parameters()) {
                pl.setParameter(parameter.getName(), parameter.getValue());
            }

            pl.setParameter("STRING", algorithm.getMacString(parameters()));
            pl.setParameter("RESULTCODE", (new Boolean(answer).toString()));
            LoggerFactory.getLogger(pl.getClass()).trace(pl.toString());
            // end logging
            return answer;

        } catch (Exception e) {
            if (e instanceof BanklinkException) {
                throw (BanklinkException) e;
            }
            throw new BanklinkException("Packet verify failed. Cause: " + e.toString(), e);
        }
    }
}
