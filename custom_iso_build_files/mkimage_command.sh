sh aports/scripts/mkimage.sh --tag 3.19 \
  --outdir ~/iso \
  --arch x86_64 \
  --repository https://dl-cdn.alpinelinux.org/alpine/v3.19/main \
  --repository https://dl-cdn.alpinelinux.org/alpine/v3.19/community \
  --repository /home/build/packages/packages \
  --profile recluster
