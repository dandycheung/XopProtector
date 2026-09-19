package com.yqsh.protector.shell;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.text.TextUtils;
import android.util.Log;

import androidx.annotation.Keep;
import androidx.annotation.Nullable;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Replace ProxyApplication with the real Application via ActivityThread / LoadedApk,
 * matching dpt-shell's replaceApplicationOnLoadedApk flow.
 */
@Keep
public final class ApplicationReplacer {
    private static final String TAG = "protector.AppReplace";

    private ApplicationReplacer() {
    }

    /**
     * @return the single real Application instance, or null on failure
     */
    @Nullable
    public static Application replace(String realApplicationClassName) {
        if (TextUtils.isEmpty(realApplicationClassName)) {
            return null;
        }
        try {
            Object activityThread = currentActivityThread();
            if (activityThread == null) {
                Log.e(TAG, "ActivityThread is null");
                return null;
            }

            Object boundApp = getField(activityThread, "mBoundApplication");
            if (boundApp == null) {
                Log.e(TAG, "mBoundApplication is null");
                return null;
            }

            Object loadedApk = getField(boundApp, "info");
            if (loadedApk == null) {
                Log.e(TAG, "LoadedApk is null");
                return null;
            }

            // installContentProviders() may already be iterating AppBindData.providers.
            // Sophix/DRouter attach often mutates that list → ConcurrentModificationException.
            // Retarget the field to a fresh copy so mutations cannot touch the live iterator.
            detachProvidersList(boundApp);

            // Clear proxy Application so makeApplication creates a new one
            setField(loadedApk, "mApplication", null);

            Object allApps = getField(activityThread, "mAllApplications");
            if (allApps instanceof List) {
                @SuppressWarnings("unchecked")
                List<Object> list = (List<Object>) allApps;
                if (!list.isEmpty()) {
                    list.remove(0);
                    Log.i(TAG, "removed proxy from mAllApplications");
                }
            }

            // ApplicationInfo.className is a binary name (dot-separated) for ClassLoader.loadClass
            ApplicationInfo loadedAi = (ApplicationInfo) getField(loadedApk, "mApplicationInfo");
            ApplicationInfo bindAi = (ApplicationInfo) getField(boundApp, "appInfo");
            if (loadedAi != null) {
                loadedAi.className = realApplicationClassName;
            }
            if (bindAi != null) {
                bindAi.className = realApplicationClassName;
            }

            Method makeApplication = loadedApk.getClass().getDeclaredMethod(
                    "makeApplication", boolean.class, Class.forName("android.app.Instrumentation"));
            makeApplication.setAccessible(true);
            Object newApp = makeApplication.invoke(loadedApk, false, null);
            if (!(newApp instanceof Application)) {
                Log.e(TAG, "makeApplication returned null/non-Application");
                return null;
            }

            Application real = (Application) newApp;
            setField(activityThread, "mInitialApplication", real);

            Object allApps2 = getField(activityThread, "mAllApplications");
            if (allApps2 instanceof List) {
                @SuppressWarnings("unchecked")
                List<Object> list = (List<Object>) allApps2;
                if (!list.contains(real)) {
                    list.add(real);
                }
            }

            Log.i(TAG, "replaced with " + real.getClass().getName());
            return real;
        } catch (Throwable t) {
            Log.e(TAG, "replace failed", t);
            return null;
        }
    }

    /**
     * Re-pin system Application pointers to an already-created real Application.
     * <p>Early {@link #replace} runs inside Proxy {@code attachBaseContext}. After that
     * returns, the outer {@code LoadedApk.makeApplication} assigns {@code mApplication}
     * / {@code mInitialApplication} back to the Proxy. Call this from Proxy
     * {@code onCreate} (after outer makeApplication finished) so
     * {@code Activity.getApplication()} / {@code Context.getApplicationContext()}
     * resolve to the real Application — without creating a second instance.
     * <p>Also migrates Application-scoped callback lists off the Proxy
     * ({@code ActivityLifecycleCallbacks} / {@code ComponentCallbacks} /
     * Assist listeners, e.g. {@code ProcessLifecycleOwner} via {@code androidx.startup})
     * onto {@code real}, otherwise process-level observers never see ON_START/ON_RESUME
     * and trim/config callbacks stay stuck on the Proxy.
     *
     * @return true if pointers were updated
     */
    public static boolean reattach(Application real) {
        return reattach(real, null);
    }

    /**
     * @param proxyHint the live ProxyApplication instance when known (preferred source
     *                  for callback-list migration)
     */
    public static boolean reattach(Application real, @Nullable Application proxyHint) {
        if (real == null) {
            return false;
        }
        try {
            Object activityThread = currentActivityThread();
            if (activityThread == null) {
                Log.e(TAG, "reattach: ActivityThread is null");
                return false;
            }

            Object boundApp = getField(activityThread, "mBoundApplication");
            if (boundApp == null) {
                Log.e(TAG, "reattach: mBoundApplication is null");
                return false;
            }

            Object loadedApk = getField(boundApp, "info");
            if (loadedApk == null) {
                Log.e(TAG, "reattach: LoadedApk is null");
                return false;
            }

            // Prefer public-API transfer from Proxy (API 34+ blocks reflecting
            // mCallbacksController). Reflection remains a fallback for odd cases.
            if (proxyHint instanceof ProxyApplication) {
                ((ProxyApplication) proxyHint).transferCallbacksTo(real);
            } else if (proxyHint != null && proxyHint != real) {
                migrateApplicationCallbacks(proxyHint, real);
            }

            setField(loadedApk, "mApplication", real);
            setField(activityThread, "mInitialApplication", real);

            Object allApps = getField(activityThread, "mAllApplications");
            if (allApps instanceof List) {
                @SuppressWarnings("unchecked")
                List<Object> list = (List<Object>) allApps;
                Iterator<Object> it = list.iterator();
                while (it.hasNext()) {
                    Object o = it.next();
                    if (!(o instanceof Application)) {
                        continue;
                    }
                    Application app = (Application) o;
                    if (app == real) {
                        continue;
                    }
                    String name = app.getClass().getName();
                    if (!name.startsWith("com.yqsh.protector.shell.")) {
                        continue;
                    }
                    if (app != proxyHint) {
                        if (app instanceof ProxyApplication) {
                            ((ProxyApplication) app).transferCallbacksTo(real);
                        } else {
                            migrateApplicationCallbacks(app, real);
                        }
                    }
                    // Point leftover Proxy ContextImpl at real before dropping it.
                    syncOuterContext(app, real);
                    it.remove();
                }
                if (!list.contains(real)) {
                    list.add(real);
                }
            }

            syncOuterContext(real, real);

            // ApplicationInfo.className may still say Proxy after packer rewrite;
            // keep it aligned with the live instance for any late framework reads.
            String realName = real.getClass().getName();
            ApplicationInfo loadedAi = (ApplicationInfo) getField(loadedApk, "mApplicationInfo");
            ApplicationInfo bindAi = (ApplicationInfo) getField(boundApp, "appInfo");
            if (loadedAi != null) {
                loadedAi.className = realName;
            }
            if (bindAi != null) {
                bindAi.className = realName;
            }

            Log.i(TAG, "reattached " + realName);
            return true;
        } catch (Throwable t) {
            Log.e(TAG, "reattach failed", t);
            return false;
        }
    }

    /**
     * Move Application-scoped callback registrations from {@code from} to {@code to}.
     * Covers Activity lifecycle, ComponentCallbacks (trim/config), and Assist listeners.
     */
    static void migrateApplicationCallbacks(Application from, Application to) {
        if (from == null || to == null || from == to) {
            return;
        }
        HiddenApiBypass.exemptAll();
        migrateActivityLifecycleCallbacks(from, to);
        migrateComponentCallbacks(from, to);
        migrateAssistCallbacks(from, to);
    }

    /**
     * Move {@link Application.ActivityLifecycleCallbacks} from {@code from} to {@code to}.
     * Required after Proxy→real Application replace so {@code ProcessLifecycleOwner}
     * (and similar early registrants) keep receiving Activity start/resume.
     */
    static void migrateActivityLifecycleCallbacks(Application from, Application to) {
        migrateApplicationListField(from, to, "mActivityLifecycleCallbacks",
                "ActivityLifecycleCallbacks");
    }

    /**
     * Move {@link android.content.ComponentCallbacks} registrations.
     * <ul>
     *   <li>API ≤ ~33: {@code Application.mComponentCallbacks}</li>
     *   <li>API 34+: {@code Application.mCallbacksController.mComponentCallbacks}</li>
     * </ul>
     */
    static void migrateComponentCallbacks(Application from, Application to) {
        // Legacy ArrayList on Application (pre ComponentCallbacksController).
        if (migrateApplicationListField(from, to, "mComponentCallbacks", "ComponentCallbacks")) {
            return;
        }
        // Android 14+: ComponentCallbacksController on Application.
        try {
            Field controllerField = Application.class.getDeclaredField("mCallbacksController");
            controllerField.setAccessible(true);
            Object fromCtrl = controllerField.get(from);
            Object toCtrl = controllerField.get(to);
            if (fromCtrl == null || toCtrl == null) {
                return;
            }
            Class<?> ctrlClz = fromCtrl.getClass();
            Field listField = ctrlClz.getDeclaredField("mComponentCallbacks");
            listField.setAccessible(true);
            Field lockField = ctrlClz.getDeclaredField("mLock");
            lockField.setAccessible(true);
            Object fromLock = lockField.get(fromCtrl);
            Object toLock = lockField.get(toCtrl);
            if (fromLock == null) {
                fromLock = fromCtrl;
            }
            if (toLock == null) {
                toLock = toCtrl;
            }
            List<Object> moved;
            synchronized (fromLock) {
                Object fromRaw = listField.get(fromCtrl);
                if (!(fromRaw instanceof List)) {
                    return;
                }
                @SuppressWarnings("unchecked")
                List<Object> fromList = (List<Object>) fromRaw;
                if (fromList.isEmpty()) {
                    return;
                }
                moved = new ArrayList<>(fromList);
                fromList.clear();
            }
            int added = 0;
            synchronized (toLock) {
                Object toRaw = listField.get(toCtrl);
                List<Object> toList;
                if (toRaw instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<Object> existing = (List<Object>) toRaw;
                    toList = existing;
                } else {
                    toList = new ArrayList<>();
                    listField.set(toCtrl, toList);
                }
                for (Object cb : moved) {
                    if (cb == null) {
                        continue;
                    }
                    if (!toList.contains(cb)) {
                        toList.add(cb);
                        added++;
                    }
                }
            }
            if (added > 0) {
                Log.i(TAG, "migrated ComponentCallbacks(controller) count=" + added
                        + " from=" + from.getClass().getName()
                        + " to=" + to.getClass().getName());
            }
        } catch (NoSuchFieldException ignored) {
            // Neither legacy nor controller field — ignore.
        } catch (Throwable t) {
            Log.w(TAG, "migrate ComponentCallbacks(controller) failed", t);
        }
    }

    /**
     * Move {@link Application.OnProvideAssistDataListener} list (nullable, sync on Application).
     */
    static void migrateAssistCallbacks(Application from, Application to) {
        try {
            Field field = Application.class.getDeclaredField("mAssistCallbacks");
            field.setAccessible(true);
            List<Object> moved;
            synchronized (from) {
                Object fromRaw = field.get(from);
                if (!(fromRaw instanceof List)) {
                    return;
                }
                @SuppressWarnings("unchecked")
                List<Object> fromList = (List<Object>) fromRaw;
                if (fromList.isEmpty()) {
                    return;
                }
                moved = new ArrayList<>(fromList);
                fromList.clear();
            }
            int added = 0;
            synchronized (to) {
                Object toRaw = field.get(to);
                List<Object> toList;
                if (toRaw instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<Object> existing = (List<Object>) toRaw;
                    toList = existing;
                } else {
                    toList = new ArrayList<>();
                    field.set(to, toList);
                }
                for (Object cb : moved) {
                    if (cb == null) {
                        continue;
                    }
                    if (!toList.contains(cb)) {
                        toList.add(cb);
                        added++;
                    }
                }
            }
            if (added > 0) {
                Log.i(TAG, "migrated AssistCallbacks count=" + added
                        + " from=" + from.getClass().getName()
                        + " to=" + to.getClass().getName());
            }
        } catch (NoSuchFieldException ignored) {
            // Older / unexpected layout.
        } catch (Throwable t) {
            Log.w(TAG, "migrate AssistCallbacks failed", t);
        }
    }

    /**
     * @return true if the named field existed (even when empty / nothing moved)
     */
    private static boolean migrateApplicationListField(Application from, Application to,
                                                       String fieldName, String label) {
        try {
            Field field = Application.class.getDeclaredField(fieldName);
            field.setAccessible(true);
            Object fromRaw = field.get(from);
            Object toRaw = field.get(to);
            if (!(fromRaw instanceof List) || !(toRaw instanceof List)) {
                Log.w(TAG, label + " list type unexpected");
                return true;
            }
            @SuppressWarnings("unchecked")
            List<Object> fromList = (List<Object>) fromRaw;
            @SuppressWarnings("unchecked")
            List<Object> toList = (List<Object>) toRaw;
            List<Object> moved;
            synchronized (fromList) {
                if (fromList.isEmpty()) {
                    return true;
                }
                moved = new ArrayList<>(fromList);
                fromList.clear();
            }
            int added = 0;
            synchronized (toList) {
                for (Object cb : moved) {
                    if (cb == null) {
                        continue;
                    }
                    if (!toList.contains(cb)) {
                        toList.add(cb);
                        added++;
                    }
                }
            }
            if (added > 0) {
                Log.i(TAG, "migrated " + label + " count=" + added
                        + " from=" + from.getClass().getName()
                        + " to=" + to.getClass().getName());
            }
            return true;
        } catch (NoSuchFieldException ignored) {
            return false;
        } catch (Throwable t) {
            Log.w(TAG, "migrate " + label + " failed", t);
            return true;
        }
    }

    /** Ensure ContextImpl.mOuterContext points at {@code real} (OEM / getApplicationContext). */
    private static void syncOuterContext(Application holder, Application real) {
        try {
            Context base = holder.getBaseContext();
            if (base != null) {
                setField(base, "mOuterContext", real);
            }
        } catch (Throwable t) {
            Log.w(TAG, "syncOuterContext failed for " + holder.getClass().getName(), t);
        }
    }

    /**
     * Point AppBindData.providers at a new ArrayList so in-flight enhanced-for
     * iteration (installContentProviders) keeps the old list identity.
     */
    private static void detachProvidersList(Object boundApp) {
        try {
            Object providers = getField(boundApp, "providers");
            if (!(providers instanceof List)) {
                return;
            }
            @SuppressWarnings("unchecked")
            List<Object> list = (List<Object>) providers;
            setField(boundApp, "providers", new ArrayList<>(list));
            Log.i(TAG, "detached providers list (size=" + list.size() + ")");
        } catch (Throwable t) {
            Log.w(TAG, "detach providers failed", t);
        }
    }

    /**
     * After providers were already installed under the replaced Application
     * (early {@code attachBaseContext} replace and/or createPackageContext path),
     * clear AppBindData.providers so Sophix {@code onCreate} does not call
     * {@code installContentProviders} again.
     * Re-install breaks InitProvider-style libs (e.g. AutoSize "can only be called once")
     * and Sophix then abandons before the business Application.onCreate runs.
     * <p>Safe only when invoked from Application.onCreate (after framework
     * Provider install). Do not call from attachBaseContext.
     */
    public static void markProvidersAlreadyInstalled() {
        try {
            Object activityThread = currentActivityThread();
            if (activityThread == null) {
                return;
            }
            Object boundApp = getField(activityThread, "mBoundApplication");
            if (boundApp == null) {
                return;
            }
            Object providers = getField(boundApp, "providers");
            int size = (providers instanceof List) ? ((List<?>) providers).size() : -1;
            // Idempotent: already empty means install finished or never scheduled.
            if (size == 0) {
                Log.i(TAG, "providers already empty before Application.onCreate");
                return;
            }
            setField(boundApp, "providers", new ArrayList<>());
            Log.i(TAG, "cleared providers before Application.onCreate (was size=" + size + ")");
        } catch (Throwable t) {
            Log.w(TAG, "markProvidersAlreadyInstalled failed", t);
        }
    }

    /**
     * Sophix may have already attached the business Application during stub attach.
     * Find that instance in {@code mAllApplications} (not proxy, not the stub itself).
     */
    @Nullable
    public static Application findBusinessApplication(@Nullable Application stubOrProxy) {
        try {
            Object activityThread = currentActivityThread();
            if (activityThread == null) {
                return null;
            }
            Object allApps = getField(activityThread, "mAllApplications");
            if (!(allApps instanceof List)) {
                return null;
            }
            @SuppressWarnings("unchecked")
            List<Object> list = (List<Object>) allApps;
            Application fallback = null;
            for (Object o : list) {
                if (!(o instanceof Application)) {
                    continue;
                }
                Application app = (Application) o;
                String name = app.getClass().getName();
                if (name.startsWith("com.yqsh.protector.shell.")) {
                    continue;
                }
                if (stubOrProxy != null && app == stubOrProxy) {
                    continue;
                }
                // Prefer non-Sophix stub (business Application).
                if (name.contains("SophixStub") || name.endsWith("SophixApplication")) {
                    if (fallback == null) {
                        fallback = app;
                    }
                    continue;
                }
                return app;
            }
            return fallback;
        } catch (Throwable t) {
            Log.w(TAG, "findBusinessApplication failed", t);
            return null;
        }
    }

    private static Object currentActivityThread() throws Exception {
        Class<?> clz = Class.forName("android.app.ActivityThread");
        Method m = clz.getDeclaredMethod("currentActivityThread");
        m.setAccessible(true);
        return m.invoke(null);
    }

    private static Object getField(Object obj, String name) throws Exception {
        Class<?> c = obj.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(obj);
            } catch (NoSuchFieldException ignored) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    private static void setField(Object obj, String name, Object value) throws Exception {
        Class<?> c = obj.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                f.set(obj, value);
                return;
            } catch (NoSuchFieldException ignored) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }
}
