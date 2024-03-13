---
icon: material/package
---

# 包管理器

## :material-tram: 仓库安装

=== ":material-debian: Debian / APT"

    ```bash
    sudo curl -fsSL https://deb.sagernet.org/gpg.key -o /etc/apt/keyrings/sagernet.asc
    sudo chmod a+r /etc/apt/keyrings/sagernet.asc
    echo "deb [arch=`dpkg --print-architecture` signed-by=/etc/apt/keyrings/sagernet.asc] https://deb.sagernet.org/ * *" | \
      sudo tee /etc/apt/sources.list.d/sagernet.list > /dev/null
    sudo apt-get update
    sudo apt-get install sing-box # or sing-box-beta
    ```

=== ":material-redhat: Redhat / DNF"

    ```bash
    sudo dnf -y install dnf-plugins-core
    sudo dnf config-manager --add-repo https://sing-box.app/rpm.repo
    sudo dnf install sing-box # or sing-box-beta
    ```

=== ":material-redhat: CentOS / YUM"

    ```bash
    sudo yum install -y yum-utils
    sudo yum-config-manager --add-repo https://sing-box.app/rpm.repo
    sudo yum install sing-box # or sing-box-beta
    ```

## :material-download-box: 手动安装

=== ":material-debian: Debian / DEB"

    ```bash
    bash <(curl -fsSL https://sing-box.app/deb-install.sh)
    ```

=== ":material-redhat: Redhat / RPM"

    ```bash
    bash <(curl -fsSL https://sing-box.app/rpm-install.sh)
    ```

=== ":simple-archlinux: Archlinux / PKG"

    ```bash
    bash <(curl -fsSL https://sing-box.app/arch-install.sh)
    ```

## :material-book-lock-open: 托管安装

=== ":material-linux: Linux"

    | 类型       | 平台         | 链接                  | 命令                           | 活跃维护             |
    |----------|------------|---------------------|------------------------------|------------------|
    | Alpine   | Alpine     | [sing-box][alpine]  | `apk add sing-box`           | :material-check: |
    | AUR      | Arch Linux | [sing-box][aur] ᴬᵁᴿ | `? -S sing-box`              | :material-check: |
    | nixpkgs  | NixOS      | [sing-box][nixpkgs] | `nix-env -iA nixos.sing-box` | :material-check: |
    | Homebrew | Linux      | [sing-box][brew]    | `brew install sing-box`      | :material-check: |

=== ":material-apple: macOS"

    | 类型       | 平台    | 链接               | 命令                      | 活跃维护             |
    |----------|-------|------------------|-------------------------|------------------|
    | Homebrew | macOS | [sing-box][brew] | `brew install sing-box` | :material-check: |

=== ":material-microsoft-windows: Windows"

    | 类型         | 平台      | 链接                 | 命令                        | 活跃维护             |
    |------------|---------|--------------------|---------------------------|------------------|
    | Scoop      | Windows | [sing-box][scoop]  | `scoop install sing-box`  | :material-check: |
    | Chocolatey | Windows | [sing-box][choco]  | `choco install sing-box`  | :material-check: |
    | winget     | Windows | [sing-box][winget] | `winget install sing-box` | :material-alert: |

=== ":material-android: Android"

    | 类型     | 平台      | 链接                 | 命令                 | 活跃维护             |
    |--------|---------|--------------------|--------------------|------------------|
    | Termux | Android | [sing-box][termux] | `pkg add sing-box` | :material-check: |

=== ":material-freebsd: FreeBSD"

    | 类型         | 平台      | 链接                | 命令                     | 活跃维护             |
    |------------|---------|-------------------|------------------------|------------------|
    | FreshPorts | FreeBSD | [sing-box][ports] | `pkg install sing-box` | :material-alert: |

## :material-book-multiple: 服务管理

对于带有 [systemd][systemd] 的 Linux 系统，通常安装已经包含 sing-box 服务，
您可以使用以下命令管理服务：

| 行动   | 命令                                            |
|------|-----------------------------------------------|
| 启用   | `sudo systemctl enable sing-box`              |
| 禁用   | `sudo systemctl disable sing-box`             |
| 启动   | `sudo systemctl start sing-box`               |
| 停止   | `sudo systemctl stop sing-box`                |
| 强行停止 | `sudo systemctl kill sing-box`                |
| 重新启动 | `sudo systemctl restart sing-box`             |
| 查看日志 | `sudo journalctl -u sing-box --output cat -e` |
| 实时日志 | `sudo journalctl -u sing-box --output cat -f` |

[alpine]: https://pkgs.alpinelinux.org/packages?name=sing-box

[aur]: https://aur.archlinux.org/packages/sing-box

[nixpkgs]: https://github.com/NixOS/nixpkgs/blob/nixos-unstable/pkgs/tools/networking/sing-box/default.nix

[brew]: https://formulae.brew.sh/formula/sing-box

[choco]: https://chocolatey.org/packages/sing-box

[scoop]: https://github.com/ScoopInstaller/Main/blob/master/bucket/sing-box.json

[winget]: https://github.com/microsoft/winget-pkgs/tree/master/manifests/s/SagerNet/sing-box

[termux]: https://github.com/termux/termux-packages/tree/master/packages/sing-box

[ports]: https://www.freshports.org/net/sing-box

[systemd]: https://systemd.io/
