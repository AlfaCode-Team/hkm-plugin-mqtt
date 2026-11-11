<?php

declare(strict_types=1);

/**
 * Test bootstrap.
 *
 * This plugin has no `vendor/` of its own: it is developed inside the plugin
 * workspace against a kernel checkout, and `composer install` here would reach
 * for the kernel on Packagist rather than use the one next door. So the suite
 * locates the kernel itself and maps this plugin's two namespaces by hand.
 *
 * THE KERNEL'S `vendor/autoload.php` IS LOADED, not just its `src/`. The kernel
 * carries its first-party path packages there — `AlfacodeTeam\Ground\` (the
 * real-kernel harness and its fakes) and `AlfaCode\LetMigrate\` — and a
 * hand-written map for this plugin alone cannot provide them.
 *
 * Order, most specific first:
 *   1. HKM_KERNEL_PATH          — an explicit checkout
 *   2. vendor/autoload.php      — composer-installed (CI)
 *   3. ../../../PHP             — the conventional workspace layout
 */

$pluginRoot = \dirname(__DIR__);

spl_autoload_register(static function (string $class) use ($pluginRoot): void {
    // The test namespace is listed first for readability. It is not matched by
    // the plugin prefix either way, but an explicit order cannot be broken by
    // someone reordering the map later.
    $map = [
        'Tests\\Unit\\Plugins\\Mqtt\\' => $pluginRoot . '/tests/',
        'Plugins\\Mqtt\\' => $pluginRoot . '/',
    ];

    foreach ($map as $prefix => $base) {
        if (!str_starts_with($class, $prefix)) {
            continue;
        }

        $relative = substr($class, \strlen($prefix));
        $path     = $base . str_replace('\\', '/', $relative) . '.php';

        if (is_file($path)) {
            require_once $path;
        }

        return;
    }
});

$kernelRoot = getenv('HKM_KERNEL_PATH') ?: null;

if ($kernelRoot === null && is_file($pluginRoot . '/vendor/autoload.php')) {
    require_once $pluginRoot . '/vendor/autoload.php';
    $kernelRoot = false; // composer-installed: everything is already on the path
}

if ($kernelRoot !== false) {
    $kernelRoot ??= \dirname($pluginRoot, 3) . '/PHP';

    if (!is_dir($kernelRoot . '/src/Kernel')) {
        fwrite(STDERR, \sprintf(
            "\nCannot find the kernel. Looked in %s.\nSet HKM_KERNEL_PATH to a checkout, or run"
            . " `composer install`.\n\n",
            $kernelRoot,
        ));
        exit(1);
    }

    if (is_file($kernelRoot . '/vendor/autoload.php')) {
        require_once $kernelRoot . '/vendor/autoload.php';
    } else {
        fwrite(STDERR, \sprintf(
            "\nFound the kernel at %s but it has no vendor/autoload.php.\n"
            . "Run `composer install` there — the suite needs Ground and LetMigrate.\n\n",
            $kernelRoot,
        ));
        exit(1);
    }

    if (is_file($kernelRoot . '/src/Kernel/Support/helpers.php')) {
        require_once $kernelRoot . '/src/Kernel/Support/helpers.php';
    }
}
