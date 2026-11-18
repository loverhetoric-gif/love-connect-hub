// LOVE connect HUB の Android 版（Kotlin）。規格書 第18章・第21章。外部部品なし（Android の標準の機能だけ）
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "LoveConnectHub"
include(":lch")
