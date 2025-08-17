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
package net.siisise.itu_t.x501;

import java.util.ArrayList;

/**
 * RFC 5280 4.1.2.4. Issuer
 * 
 * Name ::= CHOICE { rdnSequence RDNSequence }
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 */
public class RDNSequence extends ArrayList<RelativeDistinguishedName> {    
}
