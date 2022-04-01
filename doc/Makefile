PANDOC = pandoc
MANSECTION = 1
NAME = testssl
TITLE = testssl.sh

all: $(NAME).$(MANSECTION) $(NAME).$(MANSECTION).html

force: clean all

clean:
	rm -f $(NAME).$(MANSECTION) $(NAME).$(MANSECTION).html

$(NAME).$(MANSECTION): $(NAME).$(MANSECTION).md
	$(PANDOC) --standalone --to man $(NAME).$(MANSECTION).md -o $@

$(NAME).$(MANSECTION).html: template.html $(NAME).$(MANSECTION).md
	$(PANDOC) --standalone --to html5 --template template.html --metadata title="$(TITLE)" $(NAME).$(MANSECTION).md -o $@
