/*
 * Copyright 2025 okome.
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
package net.siisise.itu_t.x509;

import net.siisise.bind.format.TypeFormat;
import net.siisise.iso.asn1.tag.CHOICE;
import net.siisise.iso.asn1.tag.GeneralizedTime;
import net.siisise.iso.asn1.tag.UTCTime;

/**
 * GeneralizedTime の一部をUTCTimeとして符号化する.
 * Time ::= CHOICE {
 *      utcTime        UTCTime,
 *      generalTime    GeneralizedTime }
 * 
 * yyyyMMddhhmmssZ
 */
public class Time {

    /**
     * 無期限
     */
    public static String NON = "99991231235959Z";
    
    static long UTCBEFORE = new GeneralizedTime("19500101000000Z").getTimestamp();
    static long UTCAFTER  = new GeneralizedTime("20500101000000Z").getTimestamp();

    public long time;
    
    public Time(String code) {
        time = new GeneralizedTime(exDate(code)).toEpochMilli();
    }

    /**
     * yyyyMMddhhmmssZ 8+6+1
     * @param date
     * @return GeneralizedTime
     * ToDo: 精度
     */
    static String exDate(String date) {
        
        if ( date.length() == 13 ) { // UTCTime
            char ch = date.charAt(0);
            if (ch >= '0' && ch <= '4') { // 2049年まで
                date = "20" + date;
            } else if (ch >= '5' && ch <= '9') { // 2000年以前 存在しないが一応補完しておく
                date = "19" + date;
            } else {
                throw new java.lang.IllegalArgumentException();
            }
        }
        return date;
    }

    CHOICE toTag(long t) {
        CHOICE ch = new CHOICE();
        if ( time < UTCBEFORE || time >= UTCAFTER ) {
            ch.put("generalTime", new GeneralizedTime(t));
        } else {
            ch.put("utcTime", new UTCTime(t));
        }
        return ch;
    }

    public <T> T rebind(TypeFormat<T> format) {
        return (T)toTag(time).rebind(format);
    }
}
