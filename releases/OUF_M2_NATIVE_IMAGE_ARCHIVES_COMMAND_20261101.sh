# Historical capture succeeded and is consumed. Do not replay the retained launcher.
printf '%s\n' '{"status":"STOP_RECONCILE","reasonCode":"IMAGE_ARCHIVE_CAPTURE_ALREADY_CONSUMED_DO_NOT_REPLAY"}'
exit 2
