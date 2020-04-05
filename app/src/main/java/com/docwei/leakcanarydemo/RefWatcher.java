package com.docwei.leakcanarydemo;

import android.content.Intent;
import android.os.Debug;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.MessageQueue;
import android.util.Log;

import androidx.core.content.ContextCompat;

import com.docwei.leakcanarydemo.analyzer.HeapAnalyzerService;
import com.docwei.leakcanarydemo.analyzer.KeyedWeakReference;


import java.io.File;
import java.io.IOException;
import java.lang.ref.ReferenceQueue;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArraySet;

import static com.docwei.leakcanarydemo.analyzer.HeapAnalyzerService.HEAPDUMP_EXTRA;
import static com.docwei.leakcanarydemo.analyzer.HeapAnalyzerService.REFERENCE_KEY_EXTRA;

/* When active:   NULL
 *     pending:   this
 *    Enqueued:   next reference in queue (or this if last)
 *    Inactive:   this
 */

public class RefWatcher {
    private static final String HPROF_SUFFIX = ".hprof";
    private static final String PENDING_HEAPDUMP_SUFFIX = "_pending" + HPROF_SUFFIX;
   public static volatile RefWatcher sInstance;
    public static  RefWatcher  getInstance(){
        if(sInstance==null){
            synchronized (RefWatcher.class){
                if(sInstance==null){
                    return new RefWatcher(new CopyOnWriteArraySet<String>(),new ReferenceQueue<>());
                }
            }
        }
        return sInstance;
    }
    private final Handler mBackgroundHander;
    private final Handler mMainHandler;

    private  RefWatcher(Set<String> retainedKeys, ReferenceQueue<Object> queue) {
        this.retainedKeys = retainedKeys;
        this.queue = queue;
        HandlerThread handlerThread=new HandlerThread("watch_leak");
        handlerThread.start();
        mBackgroundHander = new Handler(handlerThread.getLooper());
        mMainHandler = new Handler(Looper.getMainLooper());

    }

    private final Set<String> retainedKeys;
    private final ReferenceQueue<Object> queue;
    public void watch(Object object) {
        if(object==null) {
            return;
        }
        String key = UUID.randomUUID().toString();
        retainedKeys.add(key);
        //将key与object绑定，所以新建了这个KeyedWeakReference;
        KeyedWeakReference weakReference=new KeyedWeakReference(object,key,queue);
        ensureGoneAsync(weakReference);
    }
    private void ensureGoneAsync(final KeyedWeakReference weakReference) {
        //leakCanary大概等了5秒时间，再去检测是否泄露的
        //参考leakCanary的搞法
        mBackgroundHander.postDelayed(new Runnable() {
            @Override
            public void run() {
                mMainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        Looper.myQueue().addIdleHandler(new MessageQueue.IdleHandler() {
                            @Override public boolean queueIdle() {
                                ensureGone(weakReference);
                                return false;
                            }
                        });
                    }
                });
            }
        },5000);

    }
    public void ensureGone(KeyedWeakReference weakReference){
        removeWeaklyReachableReferences();
        //说明对象被正常回收了
        if(!retainedKeys.contains(weakReference.key)){
            return;
        }
        //Gc一次之后
        GcTrigger.DEFAULT.runGc();
        //再清理操作
        removeWeaklyReachableReferences();

        if(retainedKeys.contains(weakReference.key)){
            Log.e("leak1", "catch a leak point "+weakReference );
            //进行内存快照 key还在说明 reference不在这个ReferenceQueue里面，可能就发生内存泄露了
            //就直接手动给存储权限
            File file=new File(MyApplication.getInstance().getExternalFilesDir("dump"),UUID.randomUUID().toString()+PENDING_HEAPDUMP_SUFFIX);
            try {
                Debug.dumpHprofData(file.getAbsolutePath());
                //leakcanary启动一个服务去解析这个profile文件
                Intent intent = new Intent(MyApplication.getInstance(), HeapAnalyzerService.class);
                intent.putExtra(HEAPDUMP_EXTRA, file.getAbsolutePath());
                intent.putExtra(REFERENCE_KEY_EXTRA, weakReference.key);
                ContextCompat.startForegroundService(MyApplication.getInstance(), intent);

            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }

    private void removeWeaklyReachableReferences() {
        // WeakReferences are enqueued as soon as the object to which they point to becomes weakly
        // reachable. This is before finalization or garbage collection has actually happened.
        //正常情况下 如果一个对象不可达了，那么这个对象的弱引用就会被加入指定的ReferenceQueue（我们可以基于此去查询对象的内存状态）中
        //如果有泄露，你清空这个是没用的，因为它不在这个ReferenceQueue里面
        KeyedWeakReference ref;
        while ((ref = (KeyedWeakReference) queue.poll()) != null) {
            //清空正常的引用对象的key。
            retainedKeys.remove(ref.key);
        }
    }
}
