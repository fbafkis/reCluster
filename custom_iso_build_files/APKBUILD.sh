pkgname=reCluster_installation
pkgver=0.1.0
pkgrel=1
pkgdesc="The reCluster release zip file."
url=""
arch="all"
license="GPL-3.0-or-later"
source="reCluster.zip"
options="!check"

package() {
    installation_path="$pkgdir"/root/
    cp -f reCluster.zip "$installation_path"
    chmod 777 "$installation_path"/reCluster.zip
}