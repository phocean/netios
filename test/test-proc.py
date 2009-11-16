from __future__ import print_function
import gtk, gobject, time, multiprocessing, Queue
class UI:
	def destroy(self, widget, data=None):
		self.outq.put("quit")
		gtk.main_quit()
	def __init__(self):
		self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
		self.window.connect("destroy", self.destroy)
		self.window.set_border_width(10)
		self.label = gtk.Label("Not Set!")
		self.window.add(self.label)
		self.label.show()
		self.window.show()
	def update(self, fd, cond):
		val = self.inq.get()
		self.label.set_text("Value is %s" % val)
		return True
	def main(self, outq, inq):
		self.outq = outq
		self.inq = inq
		# This is the tricky bit, we get the socket FD of the
		# underlying pipe from the queue object.  We hope that the
		# internal reader variable doesn't change.
		fd = inq._reader.fileno()
		# This tells GTK to watch this FD and notify us when data is
		# available.  We use newer API, gdk_input_read is deprecated
		gobject.io_add_watch(fd, gobject.IO_IN, self.update)
		gtk.main()
def counter(inq, outq, interval):
	count = 1
	again = True
	while again:
		print("Putting %s on queue" % count)
		outq.put(count)
		count += 1
		try:
			print("Reading from queue...")
			ret = inq.get(True, interval)
			if ret == "quit":
				print("Got quit message")
				again = False
		except Queue.Empty:
			# Timed-out, carry on
			pass
if __name__ == "__main__":
	q1 = multiprocessing.Queue()
	q2 = multiprocessing.Queue()
	proc = multiprocessing.Process(target=counter, args=(q1, q2, 1,))
	proc.start()
	ui = UI()
	ui.main(q1, q2)
	proc.join()
