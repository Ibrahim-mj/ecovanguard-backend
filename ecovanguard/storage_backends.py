from whitenoise.storage import CompressedManifestStaticFilesStorage

class CustomStaticFilesStorage(CompressedManifestStaticFilesStorage):
    def post_process(self, paths, dry_run=False, **options):
        # ignore errors
        try:
            yield from super().post_process(paths, dry_run, **options)
        except Exception as e:
            print(str(e))