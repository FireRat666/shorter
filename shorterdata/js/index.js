document.addEventListener('DOMContentLoaded', function () {
    const fileInput = document.getElementById('file-upload');
    const fileNameSpan = document.getElementById('file-name');

    if (fileInput && fileNameSpan) {
        fileInput.addEventListener('change', function () {
            if (this.files && this.files.length > 0) {
                fileNameSpan.textContent = this.files[0].name;
            } else {
                fileNameSpan.textContent = 'No file chosen';
            }
        });
    }
});
