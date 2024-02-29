from whitenoise.storage import CompressedManifestStaticFilesStorage
from whitenoise.storage import MissingFileError

class CustomStaticFilesStorage(CompressedManifestStaticFilesStorage):
    def post_process(self, paths, dry_run=False, **options):
        # ignore missing source map files
        for name, hashed_name, processed in super().post_process(paths, dry_run, **options):
            if isinstance(processed, MissingFileError):
                print(f"Skipping file {name} due to MissingFileError")
                continue
            yield name, hashed_name, processed