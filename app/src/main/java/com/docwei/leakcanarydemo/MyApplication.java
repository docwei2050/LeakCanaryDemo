package com.docwei.leakcanarydemo;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;




public class MyApplication extends Application {
    private static  Application instance;
    @Override
    public void onCreate() {
        super.onCreate();
        instance=this;
        registerActivityLifecycleCallbacks(new ActivityLifecycleCallbacksAdapter(){
            @Override
            public void onActivityDestroyed(Activity activity) {
               RefWatcher.getInstance().watch(activity);
            }
        });


    }
    public static Context getInstance(){
        return instance;
    }



}
