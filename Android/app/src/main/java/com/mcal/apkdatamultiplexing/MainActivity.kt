package com.mcal.apkdatamultiplexing

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.appcompat.app.AppCompatActivity
import bin.zip.DataMultiplexing
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.mcal.apkdatamultiplexing.databinding.ActivityMainBinding
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File


class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val intent =
                Intent(
                    Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                    Uri.parse("package:" + BuildConfig.APPLICATION_ID)
                )
            startActivity(intent)
        }

        binding.start.setOnClickListener {
            val inputViewText = binding.input.text.toString()
            val entryViewText = binding.entry.text.toString()
            if (entryViewText.isNotEmpty() && inputViewText.isNotEmpty() && inputViewText.endsWith(".apk")) {
                val input = File(inputViewText)
                val output = File(inputViewText.replace(".apk", "_multiplex.apk"))

                val dialog = MaterialAlertDialogBuilder(this).create()
                dialog.setTitle("Started")
                dialog.setMessage("Please wait...")
                dialog.setCancelable(false)
                dialog.show()

                CoroutineScope(Dispatchers.IO).launch {
                    try {
                        val dataMultiplexing = DataMultiplexing()
                        dataMultiplexing.startMultiplexing(input, output, inputViewText)
                    } catch (e: Exception) {
                        withContext(Dispatchers.Main) {
                            val warnDialog = MaterialAlertDialogBuilder(this@MainActivity).create()
                            warnDialog.setTitle("Warning")
                            warnDialog.setMessage(e.message.toString())
                            warnDialog.show()
                        }
                    }
                    withContext(Dispatchers.Main) {
                        dialog.dismiss()
                    }
                }
            }
        }
    }
}