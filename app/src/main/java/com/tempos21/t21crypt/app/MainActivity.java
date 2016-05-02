package com.tempos21.t21crypt.app;

import com.tempos21.t21crypt.crypter.Crypter;
import com.tempos21.t21crypt.exception.CrypterException;
import com.tempos21.t21crypt.exception.DecrypterException;
import com.tempos21.t21crypt.exception.EncrypterException;
import com.tempos21.t21crypt.factory.CryptMethod;
import com.tempos21.t21crypt.factory.CrypterFactory;

import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import tempos21.com.t21crypt.R;

public class MainActivity extends ActionBarActivity {

    /**
     * This key should be dynamic
     */
    private static final String KEY_TOKEN = "RANDOM_STRING";

    private EditText inputTxt;

    private Button encryptBtn;

    private boolean encrypt = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        inputTxt = (EditText) findViewById(R.id.inputTxt);
        encryptBtn = (Button) findViewById(R.id.encryptBtn);

        try {
            final Crypter crypter = CrypterFactory.buildCrypter(CryptMethod.AES256, KEY_TOKEN);
            encryptBtn.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    String textToCrypt = null;
                    if (encrypt) {
                        try {
                            textToCrypt = crypter.encrypt(inputTxt.getText().toString());
                        } catch (EncrypterException e) {
                            e.printStackTrace();
                        }
                        encryptBtn.setText(R.string.decrypt);
                        encrypt = !encrypt;
                    } else {
                        try {
                            textToCrypt = crypter.decrypt(inputTxt.getText().toString());
                        } catch (DecrypterException e) {
                            e.printStackTrace();
                        }
                        encryptBtn.setText(R.string.encrypt);
                        encrypt = !encrypt;
                    }
                    inputTxt.setText(textToCrypt);
                }
            });
        } catch (CrypterException e) {
            e.printStackTrace();
        }
    }
}
