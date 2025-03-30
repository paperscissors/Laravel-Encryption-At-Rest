# Contributing

Contributions are welcome and will be fully credited.

## Pull Requests

- **[PSR-12 Coding Standard](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-12-extended-coding-style-guide.md)** - The easiest way to apply the conventions is to install [PHP Code Sniffer](https://github.com/squizlabs/PHP_CodeSniffer).
- **Add tests** - Your patch won't be accepted if it doesn't have tests.
- **Document any changes in behavior** - Make sure the `README.md` and any other relevant documentation are kept up-to-date.
- **Consider our release cycle** - We try to follow [SemVer](https://semver.org/). Randomly breaking public APIs is not an option.
- **Create feature branches** - Don't ask us to pull from your master branch.
- **One pull request per feature** - If you want to do more than one thing, send multiple pull requests.
- **Send coherent history** - Make sure each individual commit in your pull request is meaningful. If you had to make multiple intermediate commits while developing, please [squash them](https://www.git-scm.com/book/en/v2/Git-Tools-Rewriting-History#Changing-Multiple-Commit-Messages) before submitting.

## Running Tests

```bash
composer test
```

## Security

If you discover any security related issues, please email security@paperscissorsandglue.com instead of using the issue tracker.

## Development Setup

1. Clone the repository
2. Run `composer install`
3. Make your changes
4. Run tests with `composer test`
5. Submit a pull request