// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets.local;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Secrets as AES-256-GCM encrypted files in one directory, the no-cloud secret store.
 *
 * <p>The same format is implemented by the server and the agent, which share the
 * directory on a single-server install. A handle is {@code local:<name>}; the file is
 * {@code <directory>/<name>.secret} holding {@code version(1) | iv(12) | ciphertext+tag}, with the
 * name as additional authenticated data so a file renamed to another secret will not decrypt.
 * Writes go to a temporary file first and are moved into place, so a reader never sees half a
 * secret.
 */
public final class LocalSecretFiles {

    public static final String HANDLE_PREFIX = "local:";
    private static final Pattern NAME = Pattern.compile("^[A-Za-z0-9_-]{1,160}$");
    private static final byte VERSION = 1;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Path directory;
    private final SecretKeySpec key;

    public LocalSecretFiles(Path directory, String base64Key) {
        if (base64Key == null || base64Key.isBlank()) {
            throw new IllegalStateException("The LOCAL secret store needs a key: set CERTPING_LOCAL_SECRET_KEY to "
                    + "the base64 of 32 random bytes (openssl rand -base64 32), the same on server and agent");
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(base64Key.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("CERTPING_LOCAL_SECRET_KEY is not valid base64", e);
        }
        if (raw.length != 32) {
            throw new IllegalStateException("CERTPING_LOCAL_SECRET_KEY must decode to 32 bytes, got " + raw.length);
        }
        this.key = new SecretKeySpec(raw, "AES");
        this.directory = directory;
        try {
            Files.createDirectories(directory);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot create the LOCAL secret store directory " + directory, e);
        }
    }

    public static boolean isHandle(String handle) {
        return handle != null && handle.startsWith(HANDLE_PREFIX) && isName(handle.substring(HANDLE_PREFIX.length()));
    }

    public static boolean isName(String name) {
        return name != null && NAME.matcher(name).matches();
    }

    public static String handleOf(String name) {
        return HANDLE_PREFIX + name;
    }

    public static String nameOf(String handle) {
        if (!isHandle(handle)) {
            throw new IllegalArgumentException("Not a LOCAL secret handle: " + handle);
        }
        return handle.substring(HANDLE_PREFIX.length());
    }

    public void write(String name, String value) throws IOException {
        requireName(name);
        byte[] iv = new byte[IV_BYTES];
        RANDOM.nextBytes(iv);
        byte[] sealed;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(name.getBytes(StandardCharsets.UTF_8));
            sealed = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Encrypting secret failed", e);
        }
        ByteBuffer out = ByteBuffer.allocate(1 + IV_BYTES + sealed.length).put(VERSION).put(iv).put(sealed);
        Path target = file(name);
        Path temp = Files.createTempFile(directory, "." + name, ".tmp");
        try {
            restrict(temp);
            Files.write(temp, out.array());
            try {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    /** Empty when no such secret exists. */
    public Optional<String> read(String name) throws IOException {
        requireName(name);
        byte[] data;
        try {
            data = Files.readAllBytes(file(name));
        } catch (NoSuchFileException e) {
            return Optional.empty();
        }
        if (data.length < 1 + IV_BYTES + TAG_BITS / 8 || data[0] != VERSION) {
            throw new IllegalStateException("Secret file for '" + name + "' is not in a known format");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, data, 1, IV_BYTES));
            cipher.updateAAD(name.getBytes(StandardCharsets.UTF_8));
            byte[] plain = cipher.doFinal(data, 1 + IV_BYTES, data.length - 1 - IV_BYTES);
            return Optional.of(new String(plain, StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Secret '" + name + "' does not decrypt with this key: the server "
                    + "and agent must share CERTPING_LOCAL_SECRET_KEY", e);
        }
    }

    public boolean exists(String name) {
        requireName(name);
        return Files.exists(file(name));
    }

    public boolean delete(String name) throws IOException {
        requireName(name);
        return Files.deleteIfExists(file(name));
    }

    private Path file(String name) {
        return directory.resolve(name + ".secret");
    }

    private static void requireName(String name) {
        if (!isName(name)) {
            throw new IllegalArgumentException("Secret name must match [A-Za-z0-9_-]{1,160}, got: " + name);
        }
    }

    private static void restrict(Path path) {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-rw----"));
        } catch (UnsupportedOperationException | IOException ignored) {
            // Not a POSIX file system; the directory's own permissions apply.
        }
    }
}
