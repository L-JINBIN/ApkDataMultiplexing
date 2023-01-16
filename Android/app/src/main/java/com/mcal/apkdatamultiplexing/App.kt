package com.mcal.apkdatamultiplexing

import android.annotation.SuppressLint
import android.app.Application
import android.content.Context

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        mContext = this
    }

    companion object {
        @SuppressLint("StaticFieldLeak")
        @JvmStatic
        private var mContext: Context? = null

        @JvmStatic
        fun getContext(): Context {
            var context = mContext
            if (context == null) {
                context = App()
                mContext = context
            }
            return context
        }
    }
}