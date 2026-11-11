// SPDX-License-Identifier: AGPL-3.0-or-later
package org.quickvault.app;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

/** Instrumentation-only ciphertext provider. Accessible only by validation49's UID. */
@SuppressWarnings("deprecation")
public final class VaultImportProvider extends ContentProvider {
    private final AtomicInteger opens = new AtomicInteger();
    private File source;
    @Override public boolean onCreate() {
        source = new File(getContext().getCacheDir(), "vault-import-ciphertext.qvault");
        return true;
    }
    private void checkCaller() {
        String target = getContext().getPackageName().replaceFirst("\\.test$", "");
        if (!"org.quickvault.validation49".equals(target)) throw new SecurityException("Isolated fixture only");
        try {
            int allowed = getContext().getPackageManager().getApplicationInfo(target, 0).uid;
            if (Binder.getCallingUid() != allowed) throw new SecurityException("Fixture caller denied");
        } catch (android.content.pm.PackageManager.NameNotFoundException e) {
            throw new SecurityException("Fixture caller unavailable");
        }
    }
    @Override public Bundle call(String method, String argument, Bundle extras) {
        checkCaller();
        Bundle result = new Bundle();
        if ("source".equals(method)) {
            ParcelFileDescriptor descriptor = extras == null ? null : (ParcelFileDescriptor)extras.getParcelable("source");
            if (descriptor == null) throw new IllegalArgumentException("Missing fixture");
            try (FileInputStream input = new ParcelFileDescriptor.AutoCloseInputStream(descriptor);
                 FileOutputStream output = new FileOutputStream(source, false)) {
                byte[] chunk = new byte[65536]; int count; long total = 0;
                while ((count = input.read(chunk)) != -1) {
                    total += count;
                    if (total > 4L * 1024 * 1024) throw new IOException("Fixture bound");
                    output.write(chunk, 0, count);
                }
                output.getFD().sync();
                opens.set(0);
            } catch (IOException e) { throw new IllegalArgumentException("Fixture setup failed"); }
        } else if ("clear".equals(method)) {
            if (source.exists() && !source.delete()) throw new IllegalArgumentException("Fixture cleanup failed");
        } else if (!"stats".equals(method)) {
            throw new IllegalArgumentException("Unknown fixture operation");
        }
        result.putInt("opens", opens.get());
        return result;
    }
    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] args, String order) {
        checkCaller();
        String[] columns = projection == null ? new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE} : projection;
        if (columns.length > 8) throw new IllegalArgumentException("Fixture columns");
        MatrixCursor cursor = new MatrixCursor(columns);
        Object[] row = new Object[columns.length];
        for (int i = 0; i < columns.length; i++) {
            if (OpenableColumns.DISPLAY_NAME.equals(columns[i])) row[i] = "Selected vault.qvault";
            // Deliberately unknown size: production must bound actual bytes.
        }
        cursor.addRow(row);
        return cursor;
    }
    @Override public String getType(Uri uri) { checkCaller(); return "application/octet-stream"; }
    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        checkCaller();
        if (!"r".equals(mode)) throw new FileNotFoundException("Read-only fixture");
        String kind = uri.getLastPathSegment();
        if ("refused".equals(kind)) throw new FileNotFoundException("Fixture refused");
        if ("denied".equals(kind)) throw new SecurityException("Fixture denied");
        if (!source.isFile()) throw new FileNotFoundException("Fixture absent");
        opens.incrementAndGet();
        if ("file".equals(kind)) return ParcelFileDescriptor.open(source, ParcelFileDescriptor.MODE_READ_ONLY);
        if (!"pipe".equals(kind) && !"slow".equals(kind) && !"malformed".equals(kind) && !"short".equals(kind)) {
            throw new FileNotFoundException("Unknown fixture");
        }
        try {
            ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
            new Thread(() -> {
                try (FileInputStream input = new FileInputStream(source);
                     FileOutputStream output = new ParcelFileDescriptor.AutoCloseOutputStream(pipe[1])) {
                    if ("malformed".equals(kind)) { output.write(new byte[]{1,2,3,4}); return; }
                    byte[] chunk = new byte["slow".equals(kind) ? 37 : 1117];
                    int count;
                    while ((count = input.read(chunk)) != -1) {
                        output.write(chunk, 0, "short".equals(kind) ? Math.min(count, 16) : count);
                        if ("short".equals(kind)) return;
                        if ("slow".equals(kind)) Thread.sleep(100);
                    }
                } catch (IOException | InterruptedException ignored) {
                    // A cancelled consumer closes its pipe; no content/errors are logged.
                }
            }, "qv-import-fixture").start();
            return pipe[0];
        } catch (IOException e) { throw new FileNotFoundException("Fixture pipe failed"); }
    }
    @Override public Uri insert(Uri uri, ContentValues values) { throw new UnsupportedOperationException(); }
    @Override public int delete(Uri uri, String selection, String[] args) { throw new UnsupportedOperationException(); }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) { throw new UnsupportedOperationException(); }
}
