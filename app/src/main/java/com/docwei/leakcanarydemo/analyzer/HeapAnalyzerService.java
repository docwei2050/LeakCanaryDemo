package com.docwei.leakcanarydemo.analyzer;

import android.app.IntentService;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.os.SystemClock;
import android.util.Log;

import androidx.annotation.Nullable;

import com.docwei.leakcanarydemo.analyzer.AndroidExcludedRefs;
import com.docwei.leakcanarydemo.analyzer.KeyedWeakReference;
import com.docwei.leakcanarydemo.analyzer.LeakNode;
import com.docwei.leakcanarydemo.analyzer.LeakReference;
import com.docwei.leakcanarydemo.analyzer.LeakTrace;
import com.docwei.leakcanarydemo.analyzer.LeakTraceElement;
import com.docwei.leakcanarydemo.analyzer.Reachability;
import com.docwei.leakcanarydemo.analyzer.ShortestPathFinder;
import com.squareup.haha.perflib.ArrayInstance;
import com.squareup.haha.perflib.ClassInstance;
import com.squareup.haha.perflib.ClassObj;
import com.squareup.haha.perflib.Field;
import com.squareup.haha.perflib.HprofParser;
import com.squareup.haha.perflib.Instance;
import com.squareup.haha.perflib.RootObj;
import com.squareup.haha.perflib.RootType;
import com.squareup.haha.perflib.Snapshot;
import com.squareup.haha.perflib.Type;
import com.squareup.haha.perflib.io.HprofBuffer;
import com.squareup.haha.perflib.io.MemoryMappedFileBuffer;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import gnu.trove.THashMap;
import gnu.trove.TObjectProcedure;

import static android.os.Build.VERSION.SDK_INT;
import static android.os.Build.VERSION_CODES.JELLY_BEAN;
import static android.os.Build.VERSION_CODES.O;
import static com.docwei.leakcanarydemo.analyzer.HahaHelper.asString;
import static com.docwei.leakcanarydemo.analyzer.HahaHelper.classInstanceValues;
import static com.docwei.leakcanarydemo.analyzer.HahaHelper.extendsThread;
import static com.docwei.leakcanarydemo.analyzer.HahaHelper.fieldValue;
import static com.docwei.leakcanarydemo.analyzer.HahaHelper.threadName;
import static com.docwei.leakcanarydemo.analyzer.HahaHelper.valueAsString;
import static com.docwei.leakcanarydemo.analyzer.LeakTraceElement.Holder.ARRAY;
import static com.docwei.leakcanarydemo.analyzer.LeakTraceElement.Holder.CLASS;
import static com.docwei.leakcanarydemo.analyzer.LeakTraceElement.Holder.OBJECT;
import static com.docwei.leakcanarydemo.analyzer.LeakTraceElement.Holder.THREAD;
import static com.docwei.leakcanarydemo.analyzer.LeakTraceElement.Type.ARRAY_ENTRY;
import static com.docwei.leakcanarydemo.analyzer.LeakTraceElement.Type.INSTANCE_FIELD;
import static com.docwei.leakcanarydemo.analyzer.LeakTraceElement.Type.STATIC_FIELD;
import static com.docwei.leakcanarydemo.analyzer.Reachability.REACHABLE;
import static com.docwei.leakcanarydemo.analyzer.Reachability.UNKNOWN;
import static com.docwei.leakcanarydemo.analyzer.Reachability.UNREACHABLE;
import static java.util.concurrent.TimeUnit.NANOSECONDS;

public final class HeapAnalyzerService extends IntentService {
    public  static final String HEAPDUMP_EXTRA = "heapdump";
    public  static final String REFERENCE_KEY_EXTRA = "reference_key";
    private static final String ANONYMOUS_CLASS_NAME_PATTERN = "^.+\\$\\d+$";
    private  List<Reachability.Inspector> reachabilityInspectors;
    /**
     * Creates an IntentService.  Invoked by your subclass's constructor.
     *
     * @param name Used to name the worker thread, important only for debugging.
     */
    public HeapAnalyzerService(String name) {
        super(name);
    }
    public HeapAnalyzerService() {
        super("heapanalyze");
    }
    private static final String NOTIFICATION_CHANNEL_ID = "leakcanary";
    @Override
    public void onCreate() {
        super.onCreate();
       reachabilityInspectors = new ArrayList<>();
        showForegroundNotification(100, 0, true,
              "LeakCanary is working");
    }

    protected void showForegroundNotification(int max, int progress, boolean indeterminate,
                                              String contentText) {
        Notification.Builder builder = new Notification.Builder(this)
                .setContentTitle("LeakCanary is working")
                .setContentText(contentText)
                .setProgress(max, progress, indeterminate);
        Notification notification = buildNotification(this, builder);
        startForeground((int) SystemClock.uptimeMillis(), notification);
    }
    public static Notification buildNotification(Context context,
                                                 Notification.Builder builder) {
        builder.setWhen(System.currentTimeMillis())
                .setOnlyAlertOnce(true);

        if (SDK_INT >= O) {
            NotificationManager notificationManager =
                    (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            NotificationChannel notificationChannel =
                    notificationManager.getNotificationChannel(NOTIFICATION_CHANNEL_ID);
            if (notificationChannel == null) {
                String channelName = "LeakCanary";
                notificationChannel = new NotificationChannel(NOTIFICATION_CHANNEL_ID, channelName,
                        NotificationManager.IMPORTANCE_DEFAULT);
                notificationManager.createNotificationChannel(notificationChannel);
            }
            builder.setChannelId(NOTIFICATION_CHANNEL_ID);
        }

        if (SDK_INT < JELLY_BEAN) {
            return builder.getNotification();
        } else {
            return builder.build();
        }
    }
    @Override
    protected void onHandleIntent(@Nullable Intent intent) {
        Log.e("leak1", "onHandleIntent: "+"启动分析服务" );
        String  heapDumpPath = (String) intent.getSerializableExtra(HEAPDUMP_EXTRA);
        String  referenceKey = (String) intent.getSerializableExtra(REFERENCE_KEY_EXTRA);
        File heapDumpFile=new File(heapDumpPath);
        if(heapDumpFile.exists()){
            HprofBuffer buffer = null;
            try {
                buffer = new MemoryMappedFileBuffer(heapDumpFile);
                HprofParser parser = new HprofParser(buffer);
                Snapshot snapshot = parser.parse();
                deduplicateGcRoots(snapshot);
                Instance leakingRef = findLeakingReference(referenceKey, snapshot);
                Log.e("leak1", "泄露的类 "+leakingRef.getClassObj().getClassName());
                // False alarm, weak reference was cleared in between key check and heap dump.
                if (leakingRef == null) {
                    String className = leakingRef.getClassObj().getClassName();
                    Log.e("leak1", "onHandleIntent: "+className +"----no leak ");
                    return;
                }
                ShortestPathFinder pathFinder = new ShortestPathFinder(AndroidExcludedRefs.createAppDefaults().build());
                ShortestPathFinder.Result result = pathFinder.findPath(snapshot, leakingRef);

                LeakTrace leakTrace = buildLeakTrace(result.leakingNode);
                Log.e("leak1", "泄露堆栈:------- "+leakTrace.toString() );
                heapDumpFile.delete();

            } catch (IOException e) {
                e.printStackTrace();
                Log.e("leak1", "onHandleIntent:e.getMessage()  "+e.getMessage() );
            }

        }
    }

    private long computeIgnoredBitmapRetainedSize(Snapshot snapshot, Instance leakingInstance) {
        long bitmapRetainedSize = 0;
        ClassObj bitmapClass = snapshot.findClass("android.graphics.Bitmap");

        for (Instance bitmapInstance : bitmapClass.getInstancesList()) {
            if (isIgnoredDominator(leakingInstance, bitmapInstance)) {
                ArrayInstance mBufferInstance = fieldValue(classInstanceValues(bitmapInstance), "mBuffer");
                // Native bitmaps have mBuffer set to null. We sadly can't account for them.
                if (mBufferInstance == null) {
                    continue;
                }
                long bufferSize = mBufferInstance.getTotalRetainedSize();
                long bitmapSize = bitmapInstance.getTotalRetainedSize();
                // Sometimes the size of the buffer isn't accounted for in the bitmap retained size. Since
                // the buffer is large, it's easy to detect by checking for bitmap size < buffer size.
                if (bitmapSize < bufferSize) {
                    bitmapSize += bufferSize;
                }
                bitmapRetainedSize += bitmapSize;
            }
        }
        return bitmapRetainedSize;
    }
    private boolean isIgnoredDominator(Instance dominator, Instance instance) {
        boolean foundNativeRoot = false;
        while (true) {
            Instance immediateDominator = instance.getImmediateDominator();
            if (immediateDominator instanceof RootObj
                    && ((RootObj) immediateDominator).getRootType() == RootType.UNKNOWN) {
                // Ignore native roots
                instance = instance.getNextInstanceToGcRoot();
                foundNativeRoot = true;
            } else {
                instance = immediateDominator;
            }
            if (instance == null) {
                return false;
            }
            if (instance == dominator) {
                return foundNativeRoot;
            }
        }
    }
    private LeakTrace buildLeakTrace(LeakNode leakingNode) {
        List<LeakTraceElement> elements = new ArrayList<>();
        // We iterate from the leak to the GC root
        LeakNode node = new LeakNode(null, null, leakingNode, null);
        while (node != null) {
            LeakTraceElement element = buildLeakElement(node);
            if (element != null) {
                elements.add(0, element);
            }
            node = node.parent;
        }

        List<Reachability> expectedReachability =
                computeExpectedReachability(elements);

        return new LeakTrace(elements, expectedReachability);
    }
    private List<Reachability> computeExpectedReachability(
            List<LeakTraceElement> elements) {
        int lastReachableElement = 0;
        int lastElementIndex = elements.size() - 1;
        int firstUnreachableElement = lastElementIndex;
        // No need to inspect the first and last element. We know the first should be reachable (gc
        // root) and the last should be unreachable (watched instance).
        elementLoop:
        for (int i = 1; i < lastElementIndex; i++) {
            LeakTraceElement element = elements.get(i);

            for (Reachability.Inspector reachabilityInspector : reachabilityInspectors) {
                Reachability reachability = reachabilityInspector.expectedReachability(element);
                if (reachability == REACHABLE) {
                    lastReachableElement = i;
                    break;
                } else if (reachability == UNREACHABLE) {
                    firstUnreachableElement = i;
                    break elementLoop;
                }
            }
        }

        List<Reachability> expectedReachability = new ArrayList<>();
        for (int i = 0; i < elements.size(); i++) {
            Reachability status;
            if (i <= lastReachableElement) {
                status = REACHABLE;
            } else if (i >= firstUnreachableElement) {
                status = UNREACHABLE;
            } else {
                status = UNKNOWN;
            }
            expectedReachability.add(status);
        }
        return expectedReachability;
    }
    private Instance findLeakingReference(String key, Snapshot snapshot) {
        ClassObj refClass = snapshot.findClass(KeyedWeakReference.class.getName());
        if (refClass == null) {
            throw new IllegalStateException(
                    "Could not find the " + KeyedWeakReference.class.getName() + " class in the heap dump.");
        }
        List<String> keysFound = new ArrayList<>();
        for (Instance instance : refClass.getInstancesList()) {
            List<ClassInstance.FieldValue> values = classInstanceValues(instance);
            Object keyFieldValue = fieldValue(values, "key");
            if (keyFieldValue == null) {
                keysFound.add(null);
                continue;
            }
            String keyCandidate = asString(keyFieldValue);
            if (keyCandidate.equals(key)) {
                return fieldValue(values, "referent");
            }
            keysFound.add(keyCandidate);
        }
        throw new IllegalStateException(
                "Could not find weak reference with key " + key + " in " + keysFound);
    }
    /**
     * Pruning duplicates reduces memory pressure from hprof bloat added in Marshmallow.
     */
    void deduplicateGcRoots(Snapshot snapshot) {
        // THashMap has a smaller memory footprint than HashMap.
        final THashMap<String, RootObj> uniqueRootMap = new THashMap<>();

        final Collection<RootObj> gcRoots = snapshot.getGCRoots();
        for (RootObj root : gcRoots) {
            String key = String.format("%s@0x%08x", root.getRootType().getName(), root.getId());;
            if (!uniqueRootMap.containsKey(key)) {
                uniqueRootMap.put(key, root);
            }
        }

        // Repopulate snapshot with unique GC roots.
        gcRoots.clear();
        uniqueRootMap.forEach(new TObjectProcedure<String>() {
            @Override public boolean execute(String key) {
                return gcRoots.add(uniqueRootMap.get(key));
            }
        });
    }

    private LeakTraceElement buildLeakElement(LeakNode node) {
        if (node.parent == null) {
            // Ignore any root node.
            return null;
        }
        Instance holder = node.parent.instance;

        if (holder instanceof RootObj) {
            return null;
        }
        LeakTraceElement.Holder holderType;
        String className;
        String extra = null;
        List<LeakReference> leakReferences = describeFields(holder);

        className = getClassName(holder);

        List<String> classHierarchy = new ArrayList<>();
        classHierarchy.add(className);
        String rootClassName = Object.class.getName();
        if (holder instanceof ClassInstance) {
            ClassObj classObj = holder.getClassObj();
            while (!(classObj = classObj.getSuperClassObj()).getClassName().equals(rootClassName)) {
                classHierarchy.add(classObj.getClassName());
            }
        }

        if (holder instanceof ClassObj) {
            holderType = CLASS;
        } else if (holder instanceof ArrayInstance) {
            holderType = ARRAY;
        } else {
            ClassObj classObj = holder.getClassObj();
            if (extendsThread(classObj)) {
                holderType = THREAD;
                String threadName = threadName(holder);
                extra = "(named '" + threadName + "')";
            } else if (className.matches(ANONYMOUS_CLASS_NAME_PATTERN)) {
                String parentClassName = classObj.getSuperClassObj().getClassName();
                if (rootClassName.equals(parentClassName)) {
                    holderType = OBJECT;
                    try {
                        // This is an anonymous class implementing an interface. The API does not give access
                        // to the interfaces implemented by the class. We check if it's in the class path and
                        // use that instead.
                        Class<?> actualClass = Class.forName(classObj.getClassName());
                        Class<?>[] interfaces = actualClass.getInterfaces();
                        if (interfaces.length > 0) {
                            Class<?> implementedInterface = interfaces[0];
                            extra = "(anonymous implementation of " + implementedInterface.getName() + ")";
                        } else {
                            extra = "(anonymous subclass of java.lang.Object)";
                        }
                    } catch (ClassNotFoundException ignored) {
                    }
                } else {
                    holderType = OBJECT;
                    // Makes it easier to figure out which anonymous class we're looking at.
                    extra = "(anonymous subclass of " + parentClassName + ")";
                }
            } else {
                holderType = OBJECT;
            }
        }
        return new LeakTraceElement(node.leakReference, holderType, classHierarchy, extra,
                node.exclusion, leakReferences);
    }
    private List<LeakReference> describeFields(Instance instance) {
        List<LeakReference> leakReferences = new ArrayList<>();
        if (instance instanceof ClassObj) {
            ClassObj classObj = (ClassObj) instance;
            for (Map.Entry<Field, Object> entry : classObj.getStaticFieldValues().entrySet()) {
                String name = entry.getKey().getName();
                String stringValue = valueAsString(entry.getValue());
                leakReferences.add(new LeakReference(STATIC_FIELD, name, stringValue));
            }
        } else if (instance instanceof ArrayInstance) {
            ArrayInstance arrayInstance = (ArrayInstance) instance;
            if (arrayInstance.getArrayType() == Type.OBJECT) {
                Object[] values = arrayInstance.getValues();
                for (int i = 0; i < values.length; i++) {
                    String name = Integer.toString(i);
                    String stringValue = valueAsString(values[i]);
                    leakReferences.add(new LeakReference(ARRAY_ENTRY, name, stringValue));
                }
            }
        } else {
            ClassObj classObj = instance.getClassObj();
            for (Map.Entry<Field, Object> entry : classObj.getStaticFieldValues().entrySet()) {
                String name = entry.getKey().getName();
                String stringValue = valueAsString(entry.getValue());
                leakReferences.add(new LeakReference(STATIC_FIELD, name, stringValue));
            }
            ClassInstance classInstance = (ClassInstance) instance;
            for (ClassInstance.FieldValue field : classInstance.getValues()) {
                String name = field.getField().getName();
                String stringValue = valueAsString(field.getValue());
                leakReferences.add(new LeakReference(INSTANCE_FIELD, name, stringValue));
            }
        }
        return leakReferences;
    }

    private String getClassName(Instance instance) {
        String className;
        if (instance instanceof ClassObj) {
            ClassObj classObj = (ClassObj) instance;
            className = classObj.getClassName();
        } else if (instance instanceof ArrayInstance) {
            ArrayInstance arrayInstance = (ArrayInstance) instance;
            className = arrayInstance.getClassObj().getClassName();
        } else {
            ClassObj classObj = instance.getClassObj();
            className = classObj.getClassName();
        }
        return className;
    }
    @Override public void onDestroy() {
        super.onDestroy();
        stopForeground(true);
    }

}
