package org.fjarcodecore.qt;

import android.os.Bundle;
import android.system.ErrnoException;
import android.system.Os;

import org.qtproject.qt5.android.bindings.QtActivity;

import java.io.File;

public class FjarcodeQtActivity extends QtActivity
{
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        final File fjarcodeDir = new File(getFilesDir().getAbsolutePath() + "/.fjarcode");
        if (!fjarcodeDir.exists()) {
            fjarcodeDir.mkdir();
        }

        super.onCreate(savedInstanceState);
    }
}
