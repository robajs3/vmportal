# Obraz sesji przeglądarki: neko (WebRTC) + Chromium z profilem, maskowaniem fingerprintu
# i zdalnym debugowaniem tylko na 127.0.0.1 (dla runnera skryptów).
ARG BASE_IMAGE=ghcr.io/m1k1o/neko/chromium:latest
FROM $BASE_IMAGE

COPY fpext /opt/fpext
COPY br-launch.sh /usr/local/bin/br-launch.sh
COPY supervisord.conf /etc/neko/supervisord/chromium.conf
# polityki bazowe; polityki sesji (lista wtyczek) launcher dopisuje jako session.json
COPY policies.base.json /etc/chromium/policies/managed/policies.json
RUN chmod 755 /usr/local/bin/br-launch.sh \
    && mkdir -p /extensions /home/neko/.config/chromium \
    && chown -R neko:neko /extensions /home/neko/.config \
    && chown neko:neko /etc/chromium/policies/managed
