"""命令行：click。"""
import click


@click.command()
@click.option("--month", default="2026-09")
def main(month):
    click.echo(f"生成 {month} 报表")


if __name__ == "__main__":
    main()
