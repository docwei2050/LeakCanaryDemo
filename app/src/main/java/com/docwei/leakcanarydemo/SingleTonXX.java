package com.docwei.leakcanarydemo;

import android.content.Context;

public class SingleTonXX {
    // 只是为了制造内存泄露用
    public static Context mContext;
    private SingleTonXX() {
    }
    private static volatile SingleTonXX sSingleTonXX;
    public static SingleTonXX getInstance(Context context) {
        if (sSingleTonXX == null) {
            synchronized (SingleTonXX.class) {
                if (sSingleTonXX == null) {
                    //注释掉就不会导致内存泄露了
                    mContext=context;
                    return new SingleTonXX();
                }
            }
        }
        return sSingleTonXX;
    }
}
