# Generated by Django 5.0 on 2025-02-05 09:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0003_newsandevents_summary_es_newsandevents_summary_fr_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="newsandevents",
            name="summary",
            field=models.TextField(blank=True, max_length=1000, null=True),
        ),
        migrations.AlterField(
            model_name="newsandevents",
            name="summary_en",
            field=models.TextField(blank=True, max_length=1000, null=True),
        ),
        migrations.AlterField(
            model_name="newsandevents",
            name="summary_es",
            field=models.TextField(blank=True, max_length=1000, null=True),
        ),
        migrations.AlterField(
            model_name="newsandevents",
            name="summary_fr",
            field=models.TextField(blank=True, max_length=1000, null=True),
        ),
        migrations.AlterField(
            model_name="newsandevents",
            name="summary_ru",
            field=models.TextField(blank=True, max_length=1000, null=True),
        ),
        migrations.AlterField(
            model_name="newsandevents",
            name="title",
            field=models.CharField(max_length=1000, null=True),
        ),
        migrations.AlterField(
            model_name="newsandevents",
            name="title_en",
            field=models.CharField(max_length=1000, null=True),
        ),
        migrations.AlterField(
            model_name="newsandevents",
            name="title_es",
            field=models.CharField(max_length=1000, null=True),
        ),
        migrations.AlterField(
            model_name="newsandevents",
            name="title_fr",
            field=models.CharField(max_length=1000, null=True),
        ),
        migrations.AlterField(
            model_name="newsandevents",
            name="title_ru",
            field=models.CharField(max_length=1000, null=True),
        ),
    ]
