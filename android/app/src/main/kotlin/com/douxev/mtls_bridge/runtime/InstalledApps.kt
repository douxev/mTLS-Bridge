package com.douxev.mtls_bridge.runtime

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.douxev.mtls_bridge.ui.add.InstalledApp

/**
 * Apps utilisables comme cible : lançables depuis le launcher du téléphone
 * (LAUNCHER) **ou** depuis celui d'Android TV (LEANBACK_LAUNCHER). Les apps
 * réservées à la TV comme `org.jellyfin.androidtv` n'ont souvent que la
 * seconde et passeraient sinon à la trappe.
 *
 * Appel bloquant (PackageManager) : à exécuter hors du thread principal.
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

    /** Intent de lancement : launcher classique d'abord, puis Android TV. */
    fun launchIntent(pm: PackageManager, packageName: String): Intent? =
        pm.getLaunchIntentForPackage(packageName)
            ?: pm.getLeanbackLaunchIntentForPackage(packageName)

    fun label(pm: PackageManager, packageName: String): String? = try {
        pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0)).toString()
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }
}
