/**
 * Copyright 2014 Nortal AS
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.nortal.banklink.core.packet;

import com.nortal.banklink.core.BanklinkException;
import com.nortal.banklink.core.algorithm.Algorithm;
import com.nortal.banklink.core.log.PacketForwardLog;
import com.nortal.banklink.core.log.PacketLog;
import com.nortal.banklink.core.log.PacketSignLog;
import com.nortal.banklink.core.log.PacketVerifyLog;
import com.nortal.banklink.core.packet.param.PacketParameter;
import com.nortal.banklink.core.packet.verify.PacketDateAndTimeVerifier;
import com.nortal.banklink.core.packet.verify.PacketDateTimeVerifier;
import com.nortal.banklink.core.packet.verify.PacketNonceVerifier;
import com.nortal.banklink.core.packet.verify.PacketVerifier;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/*
 *  NR    DATE        AUTHOR									DESCRIPTION
 *  4     06.02.14    Lauri Lättemäe          Replaced logging logic with log4j implementation. Log messages are constructed by
 *                                            {@link PacketLog} keeping same format as FileLogger or BanklinkCategory
 *                                            for backwards compatibility. To enable operations logs globally add log4j configuration
 *                                            for package com.nortal.banklink.core.log with debug level DEBUG. To enable operation
 *                                            specific logging add separate log4j configurations with debug level DEBUG for
 *                                            {@link PacketSignLog}, {@link PacketVerifyLog} or {@link PacketForwardLog} as necessary.
 *	3			22.04.02		Ago Meister							Removed config object from class.
 *  2			07.08.01		Vladimir Tsastsin				added getInstance
 *  1			07.08.01		Vladimir Tsastsin				Class finished
 */

/**
 * A Packet class. Abstract class of all Packets.
 *
 * @author Vladimir Tsastsin
 * @author Alrik Peets
 */
public class Packet {
    /** The Constant DEFAULT_VERIFIERS. */
    private static final List<PacketVerifier> DEFAULT_VERIFIERS = new ArrayList<>();

    static {
        DEFAULT_VERIFIERS.add(new PacketDateAndTimeVerifier());
        DEFAULT_VERIFIERS.add(new PacketNonceVerifier());
        DEFAULT_VERIFIERS.add(new PacketDateTimeVerifier());
    }

    /** Crypto algorithm. */
    protected final Algorithm<?, ?> algorithm;
    /** The nonce manager. */
    protected final NonceManager nonceManager;
    /** All PacketParameters of Packet. */
    private final PacketParameterMap parameters = new PacketParameterMap();
    /** The packet id. */
    private final String packetId;
    /** Answer from server to which query was sent (Headers). */
    private String serverHeader;
    private String reEncoding;
    /** The mac name. */
    private String macName = "VK_MAC";

    /**
     * Contractor. Create Packet with specified algorithm and conguration
     *
     * @param packetId
     *            the packet id
     * @param algorithm
     *            Packet's algorithm
     */
    protected Packet(String packetId, Algorithm<?, ?> algorithm) {
        this(packetId, algorithm, (NonceManager) null);
    }

    /**
     * Contractor. Create Packet with specified algorithm and conguration
     *
     * @param packetId
     *            the packet id
     * @param algorithm
     *            Packet's algorithm
     * @param nonceManager
     *            the nonce manager
     */
    protected Packet(String packetId, Algorithm<?, ?> algorithm, NonceManager nonceManager) {
        this.algorithm = algorithm;
        this.packetId = packetId;
        this.nonceManager = nonceManager;
        init();
    }

    public String getPacketId() {
        return packetId;
    }

    /**
     * Sign m_parameters (which m_isMac) and write the signature to m_parameters
     * to MAC key.
     *
     * @throws BanklinkException
     *             the banklink exception
     */
    public void sign() throws BanklinkException {
        try {
            String MAC = algorithm.sign(parameters());
            // begin logging
            PacketLog pl = new PacketSignLog();
            for (PacketParameter parameter : parameters()) {
                pl.setParameter(parameter.getName(), parameter.getValue());
            }
            pl.setParameter("STRING", algorithm.getMacString(parameters()));
            pl.setParameter("SIGNATURE", MAC);
            LoggerFactory.getLogger(pl.getClass()).debug(pl.toString());
            // end logging
            setParameter(getMacName(), MAC);
        } catch (Exception e) {
            throw new BanklinkException(e.toString(), e);
        }
    }

    /**
     * Check if the MAC value is equal to signature of m_parameters.
     *
     * @return <PRE>
     * true
     * </PRE>
     *
     *         if digital signature is correct and
     *
     *         <PRE>
     * false
     * </PRE>
     *
     *         otherwise
     * @throws BanklinkException
     *             the banklink exception
     */

    public boolean verify() throws BanklinkException {
        return verify(DEFAULT_VERIFIERS);
    }

    /**
     * Verify.
     *
     * @param verifiers
     *            the verifiers
     * @return true, if successful
     * @throws BanklinkException
     *             the banklink exception
     */
    public boolean verify(List<PacketVerifier> verifiers) throws BanklinkException {
        try {
            String MAC = getParameterValue(getMacName());
            boolean answer = algorithm.verify(parameters(), MAC);

            if (!answer) {
                logPacketVerifyAttempt(answer);
                return false;
            }

            if (CollectionUtils.isNotEmpty(verifiers))
                for (PacketVerifier verifier : verifiers)
                    answer &= verifier.verify(this);

            logPacketVerifyAttempt(answer);

            return answer;
        } catch (Exception e) {
            if (e instanceof BanklinkException) {
                throw (BanklinkException) e;
            }
            throw new BanklinkException("Packet verify failed. Cause: " + e.toString(), e);
        }
    }

    private void logPacketVerifyAttempt(boolean answer) {
        // begin logging
        PacketLog pl = new PacketVerifyLog();
        pl.setParameter("RECODEDFROM", reEncoding);

        for (PacketParameter parameter : parameters()) {
            pl.setParameter(parameter.getName(), parameter.getValue());
        }

        pl.setParameter("STRING", algorithm.getMacString(parameters()));
        pl.setParameter("RESULTCODE", (new Boolean(answer).toString()));
        LoggerFactory.getLogger(pl.getClass()).debug(pl.toString());
        // end logging
    }

    /**
     * Gets the mac name.
     *
     * @return MAC parameter name
     */
    public String getMacName() {
        return macName;
    }

    /**
     * Sets the mac name.
     *
     * @param macName
     *            the new mac name
     */
    public void setMacName(String macName) {
        this.macName = macName;
    }

    /**
     * Generate nonce.
     *
     * @return the string
     */
    public String generateNonce() {
        if (nonceManager != null) {
            return nonceManager.generateNonce();
        }
        return null;
    }

    /**
     * Verify nonce.
     *
     * @param nonce
     *            the nonce
     * @return true, if successful
     */
    public boolean verifyNonce(String nonce) {
        if (nonceManager != null) {
            return nonceManager.verifyNonce(nonce);
        }
        return false;
    }

    /** Initialization. */
    public void init() {
        parameters.reset();
    }

    /**
     * Initialization. Get from request all require paramerets and save their
     * values to PacketParameters (can be any extended class).
     *
     * @param request
     *            HttpServletRequest from which all parameters will be received
     * @throws InvalidParameterException
     *             the invalid parameter exception
     */
    public void init(HttpServletRequest request) throws InvalidParameterException {
        init(request, "UTF-8");
    }

    public void init(HttpServletRequest request, String reencodeFrom) throws InvalidParameterException {
        init();
        this.reEncoding = reencodeFrom;
        parameters.init(request, getMacName(), reencodeFrom);
    }

    /**
     * Parameters.
     *
     * @return the list
     */
    public List<PacketParameter> parameters() {
        return parameters.parameters();
    }

    /**
     * Return value of specified key.
     *
     * @param key
     *            name of key
     * @return value value of specified key or null if the parameter does not
     *         exist or the key is null
     */

    public String getParameterValue(String key) {
        return parameters.getParameterValue(key);
    }

    /**
     * Set value of specified key.
     *
     * @param key
     *            name of key
     * @param value
     *            value which to set to specified key
     * @throws InvalidParameterException
     *             the invalid parameter exception
     */
    public void setParameter(String key, String value) throws InvalidParameterException {
        parameters.setParameter(key, value);
    }

    /**
     * Checks for parameter.
     *
     * @param key
     *            the key
     * @return true, if successful
     */
    public boolean hasParameter(String key) {
        return parameters.containsKey(key);
    }

    /**
     * Adds the packet parameter.
     *
     * @param packetParameter
     *            the packet parameter
     */
    protected void addPacketParameter(PacketParameter packetParameter) {
        parameters.put(packetParameter);
    }

    /**
     * Gets the server header.
     *
     * @return the server header
     */
    public String getServerHeader() {
        return serverHeader;
    }

    /**
     * Sets the server header.
     *
     * @param serverHeader
     *            the new server header
     */
    public void setServerHeader(String serverHeader) {
        this.serverHeader = serverHeader;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "Packet" + packetId + " " + parameters.toString();
    }

    /**
     * Log forward requests.
     *
     * @param channel
     *            HTTP or HTTPS
     * @param destination
     *            url to which data must be sent
     * @throws BanklinkException
     *             the banklink exception
     */
    public void logForward(String channel, String destination) throws BanklinkException {
        // begin logging
        PacketLog pl = new PacketForwardLog();
        for (PacketParameter parameter : parameters()) {
            pl.setParameter(parameter.getName(), parameter.getValue());
        }
        pl.setParameter("STRING", algorithm.getMacString(parameters()));
        pl.setParameter("CHANNEL", channel);
        pl.setParameter("DESTINATION", destination);
        LoggerFactory.getLogger(pl.getClass()).debug(pl.toString());
        // end logging
    }

    /**
     * Return string as HTML formatted form with all necessary field which must be
     * in that kind of form.
     *
     * @return String as HTML formated form with all necessary field which must be
     *         in that kind of form.
     */
    public String html() {
        String formString = "";
        for (PacketParameter packetParameter : parameters()) {
            formString += " <input type=\"hidden\" name=\"" + packetParameter.getName() + "\" value=\""
                    + packetParameter.getValue() + "\"/>\n";
        }
        return formString;
    }

    /**
     * Json.
     *
     * @return the string
     */
    public String json() {
        String json = "{";
        for (Iterator<PacketParameter> it = parameters().iterator(); it.hasNext(); ) {
            PacketParameter par = it.next();
            json += "\"" + par.getName() + "\":\"" + StringEscapeUtils.escapeJson(par.getValue()) + "\"";
            if (it.hasNext())
                json += ",";
        }
        json += "}";
        return json;
    }

}
