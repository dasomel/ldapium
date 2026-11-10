/* Markers outside the region must not count: slap_entry2mods diff_done SLAP_ATTR_IXADD */
retry_diff:
	if ( retry ) {
		goto retry_diff;
	}
