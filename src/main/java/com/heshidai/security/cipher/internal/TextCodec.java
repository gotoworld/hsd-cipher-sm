package com.heshidai.security.cipher.internal;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;

/** Internal text conversion that never silently replaces unmappable characters or malformed bytes. */
public final class TextCodec {
    private TextCodec() { }
    public static byte[] encode(String input, Charset charset) {
        Checks.required(input, "text"); Checks.required(charset, "charset");
        try {
            ByteBuffer buffer = charset.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(input));
            byte[] result = new byte[buffer.remaining()]; buffer.get(result); return result;
        } catch (CharacterCodingException e) { throw new IllegalArgumentException("Text cannot be represented in the selected charset", e); }
    }
    public static String decode(byte[] input, Charset charset) {
        Checks.required(input, "bytes"); Checks.required(charset, "charset");
        try {
            return charset.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(input)).toString();
        } catch (CharacterCodingException e) { throw new IllegalArgumentException("Invalid text for the selected charset", e); }
    }
}
