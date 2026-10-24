package com.douxev.mtls_bridge.ui.navigation

import androidx.compose.runtime.Composable
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.douxev.mtls_bridge.ui.add.AddConfigScreen
import com.douxev.mtls_bridge.ui.compare.CompareModesScreen
import com.douxev.mtls_bridge.ui.detail.ConfigDetailScreen
import com.douxev.mtls_bridge.ui.detail.ConfigDetailViewModel
import com.douxev.mtls_bridge.ui.edit.EditConfigScreen
import com.douxev.mtls_bridge.ui.edit.EditConfigViewModel
import com.douxev.mtls_bridge.ui.help.HelpScreen
import com.douxev.mtls_bridge.ui.list.ConfigListScreen
import com.douxev.mtls_bridge.ui.remote.RemoteAdminScreen

private object Routes {
    const val LIST = "list"
    const val ADD = "add"
    const val DETAIL = "detail/{configId}"
    const val EDIT = "edit/{configId}"
    const val COMPARE = "compare"
    const val HELP = "help"
    const val REMOTE = "remote"
    fun detail(configId: String) = "detail/$configId"
    fun edit(configId: String) = "edit/$configId"
}

@Composable
fun MtlsNavigation() {
    val nav = rememberNavController()
    NavHost(navController = nav, startDestination = Routes.LIST) {
        composable(Routes.LIST) {
            ConfigListScreen(
                onAddClick = { nav.navigate(Routes.ADD) },
                onConfigClick = { id -> nav.navigate(Routes.detail(id)) },
                onEditClick = { id -> nav.navigate(Routes.edit(id)) },
                onHelpClick = { nav.navigate(Routes.HELP) },
                onRemoteClick = { nav.navigate(Routes.REMOTE) },
            )
        }
        composable(Routes.ADD) {
            AddConfigScreen(
                onBack = { nav.popBackStack() },
                onSaved = { nav.popBackStack() },
                onCompareModes = { nav.navigate(Routes.COMPARE) },
                onRemoteClick = { nav.navigate(Routes.REMOTE) },
            )
        }
        composable(Routes.REMOTE) {
            RemoteAdminScreen(onBack = { nav.popBackStack() })
        }
        composable(Routes.COMPARE) {
            CompareModesScreen(onBack = { nav.popBackStack() })
        }
        composable(Routes.HELP) {
            HelpScreen(
                onBack = { nav.popBackStack() },
                onCompareModes = { nav.navigate(Routes.COMPARE) },
            )
        }
        composable(
            route = Routes.DETAIL,
            arguments = listOf(navArgument(ConfigDetailViewModel.CONFIG_ID_KEY) {
                type = NavType.StringType
            }),
        ) {
            ConfigDetailScreen(onBack = { nav.popBackStack() })
        }
        composable(
            route = Routes.EDIT,
            arguments = listOf(navArgument(EditConfigViewModel.CONFIG_ID_KEY) {
                type = NavType.StringType
            }),
        ) {
            EditConfigScreen(
                onBack = { nav.popBackStack() },
                onSaved = { nav.popBackStack() },
            )
        }
    }
}
