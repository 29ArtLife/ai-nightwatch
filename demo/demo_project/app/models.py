"""数据模型：SQLAlchemy。"""
import sqlalchemy as sa

metadata = sa.MetaData()
reports = sa.Table("reports", metadata, sa.Column("id", sa.Integer, primary_key=True))
