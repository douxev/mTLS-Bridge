package com.douxev.mtls_bridge.runtime

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.douxev.mtls_bridge.ui.add.InstalledApp

/**
 * Apps usable as a target: launchable from the phone launcher (LAUNCHER)
 * **or** from the Android TV one (LEANBACK_LAUNCHER). TV-only apps such as
 * `org.jellyfin.androidtv` often only have the latter and would otherwise be
 * left out.
 *
 * Blocking call (PackageManager): run it off the main thread.
 */
object InstalledApps {

    fun launchable(pm: PackageManager, selfPackage: String): List<InstalledApp> =
        pm.getInstalledApplications(0)
            .asSequence()
            .filter { it.packageName != selfPackage }
            .filter {
                it.flags and ApplicationInfo.FLAG_SYSTEM == 0 ||
                    it.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
            }
            .filter { launchIntent(pm, it.packageName) != null }
            .map { InstalledApp(packageName = it.packageName, label = pm.getApplicationLabel(it).toString()) }
            .sortedBy { it.label.lowercase() }
            .toList()

    /** Launch intent: regular launcher first, then Android TV. */
    fun launchIntent(pm: PackageManager, packageName: String): Intent? =
        pm.getLaunchIntentForPackage(packageName)
            ?: pm.getLeanbackLaunchIntentForPackage(packageName)

    fun label(pm: PackageManager, packageName: String): String? = try {
        pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0)).toString()
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }
}
