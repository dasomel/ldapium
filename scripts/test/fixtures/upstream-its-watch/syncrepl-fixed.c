retry_diff:
	slap_entry2mods( entry, &mods, &text, textbuf, textlen );
	if ( retry ) {
		goto retry_diff;
	}
