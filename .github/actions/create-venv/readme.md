# Create venv

Creates a venv in the runner temporary path that will be removed upon completion of the job.
This can be used in combination with the `activate-venv` action such as shown below.

```yaml
- uses: Chia-Network/actions/create-venv@main
  id: create-venv

- uses: Chia-Network/actions/activate-venv@main
  with:
    directories: ${{ steps.create-venv.outputs.activate-venv-directories }}
```

copied from https://github.com/Chia-Network/actions/tree/5851777428fb98585ae9628b7dc49ed9f6487fde/create-venv
