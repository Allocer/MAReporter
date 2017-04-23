from django.core.management import BaseCommand


class Command(BaseCommand):
    args = 'Arguments is not needed'
    help = 'Malware Analysis Reporter'

    def handle(self, *args, **options):
        self.stdout.write("Pomoc:\n1. Nalezy zainstalowac baze PostgreSQL, aby moc korzystac z aplikacji.\n2. Po przejsciu do folderu MalwareAnalystReporter, "
                          "aplikacje mozna uruchomic poleceniem: python manage.py runserver <port> (UWAGA: domyslny port to 8000) lub shift+F10 w PyCharm\n3. Aplikacja znajduje sie pod adresem: "
                          "localhost:<port>/reporter\n4. Po stworzeniu formularza, ktorego niektore pola sa wymagane, zostanie zapisany on w bazie danych. "
                          "Nastepnie mozna taki formularz wygenerowac jako plik PDF.\n5. Aby uzyskac pomoc nalezy uzyc komendy: python manage.py reporter_info")
