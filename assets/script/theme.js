function toggleTheme(theme) {
    // Set the theme value in the hidden input field
    document.getElementById('theme-input').value = theme;
    // Submit the form to update the theme
    document.getElementById('theme-form').submit();
}